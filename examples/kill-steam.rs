use com::runtime::init_runtime;
use netfw::{
    FirewallAction,
    FirewallPolicy,
    FirewallRule,
    FirewallRuleDirection,
};
use std::{
    ffi::OsStr,
    iter::once,
    os::windows::ffi::OsStrExt,
};
use winapi::{
    shared::minwindef::{
        BOOL,
        TRUE,
    },
    um::{
        shellapi::ShellExecuteW,
        winuser::SW_SHOWNORMAL,
    },
};

extern "system" {
    pub fn IsUserAnAdmin() -> BOOL;
}

const MAX_TRIES: usize = 3;
const RULE_NAME: &str = "_01 Block steam(Program)";

pub fn get_kill_steam_firewall_rules(
    steam_path: &OsStr,
) -> Result<Vec<FirewallRule>, std::io::Error> {
    let mut ret = Vec::with_capacity(4);

    let rule1 = FirewallRule::new()?;
    rule1.set_name(RULE_NAME)?;
    rule1.set_application_name(steam_path)?;
    rule1.set_remote_addresses("192.168.2.250-254.254.254.253")?;
    rule1.set_direction(FirewallRuleDirection::Out)?;
    rule1.set_action(FirewallAction::Block)?;
    rule1.set_enabled(true)?;

    let rule2 = FirewallRule::new()?;
    rule2.set_name(RULE_NAME)?;
    rule2.set_application_name(steam_path)?;
    rule2.set_remote_addresses("0.0.0.0-191.254.254.254")?;
    rule2.set_direction(FirewallRuleDirection::Out)?;
    rule2.set_action(FirewallAction::Block)?;
    rule2.set_enabled(true)?;

    let rule3 = FirewallRule::new()?;
    rule3.set_name(RULE_NAME)?;
    rule3.set_application_name(steam_path)?;
    rule3.set_remote_addresses("192.168.2.250-254.254.254.253")?;
    rule3.set_direction(FirewallRuleDirection::In)?;
    rule3.set_action(FirewallAction::Block)?;
    rule3.set_enabled(true)?;

    let rule4 = FirewallRule::new()?;
    rule4.set_name(RULE_NAME)?;
    rule4.set_application_name(steam_path)?;
    rule4.set_remote_addresses("0.0.0.0-191.254.254.254")?;
    rule4.set_direction(FirewallRuleDirection::In)?;
    rule4.set_action(FirewallAction::Block)?;
    rule4.set_enabled(true)?;

    ret.push(rule1);
    ret.push(rule2);
    ret.push(rule3);
    ret.push(rule4);

    Ok(ret)
}

fn pause() {
    unsafe {
        libc::system("PAUSE\0".as_ptr() as *const _);
    }
}

fn is_user_an_admin() -> bool {
    unsafe { IsUserAnAdmin() == TRUE }
}

fn try_elevate(file: &OsStr, try_count: usize) -> Result<bool, std::io::Error> {
    if is_user_an_admin() {
        return Ok(true);
    }

    let operation: Vec<u16> = OsStr::new("runas").encode_wide().chain(once(0)).collect();
    let file: Vec<u16> = file.encode_wide().chain(once(0)).collect();
    let params: Vec<u16> = OsStr::new(&(try_count).to_string())
        .encode_wide()
        .chain(once(0))
        .collect();

    let ret = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        ) as i32
    };

    if ret <= 32 {
        return Err(std::io::Error::from_raw_os_error(ret));
    }

    Ok(false)
}

fn main() {
    if let Err(e) = init_runtime() {
        eprintln!("Failed to init COM Runtime: {}", e);
        return;
    }

    // Restart as Admin
    {
        let mut os_args = std::env::args_os();
        let exe_name = match os_args.next() {
            Some(name) => name,
            None => {
                eprintln!("Missing exe name in args");
                return;
            }
        };

        let try_count: usize = os_args
            .next()
            .and_then(|s| s.to_str()?.parse().ok())
            .unwrap_or(0);

        match try_elevate(&exe_name, try_count + 1) {
            Ok(false) => {
                eprintln!("Not admin.");
                if try_count == MAX_TRIES {
                    eprintln!("Failed to restart as admin. Exiting...");
                } else {
                    eprintln!("Restarting as admin...");
                }

                return;
            }
            Ok(true) => {
                // We are admin
            }
            Err(e) => {
                eprintln!("Failed to elevate: {:#?}", e);
            }
        }
    }

    real_main();

    // Waiting on I/O deadlocks after the ctrl-c handler for some reason
    pause();
}

fn real_main() {
    let firewall_policy = match FirewallPolicy::new() {
        Ok(policy) => policy,
        Err(e) => {
            eprintln!("Failed to create firewall policy: {}", e);
            return;
        }
    };

    let firewall_rules = match firewall_policy.get_rules() {
        Ok(rules) => rules,
        Err(e) => {
            eprintln!("Failed to get firewall rules: {}", e);
            return;
        }
    };

    // TODO: Look/ask for steam path
    let steam_path = "C:\\Program Files (x86)\\Steam\\steam.exe";

    let steam_rules = match get_kill_steam_firewall_rules(steam_path.as_ref()) {
        Ok(rules) => rules,
        Err(e) => {
            eprintln!("Failed to generate steam rules: {}", e);
            return;
        }
    };

    println!("Adding Firewall Rules...");
    for rule in steam_rules {
        if let Err(e) = firewall_rules.add(rule) {
            eprintln!("Failed to add firewall rule: {}", e);
            return;
        }
    }

    println!("Added 4 Firewall Rules");

    pause();

    let num_rules = {
        let firewall_iter = match firewall_rules.iter() {
            Ok(iter) => iter,
            Err(e) => {
                eprintln!("Failed to iterate firewall rules: {}", e);
                return;
            }
        };

        let mut count = 0;

        for firewall_rule in firewall_iter {
            let firewall_rule = match firewall_rule {
                Ok(rule) => rule,
                Err(e) => {
                    eprintln!("Failed to get Firewall Rule: {}", e);
                    return;
                }
            };

            let name = match firewall_rule.get_name() {
                Ok(name) => name,
                Err(e) => {
                    eprintln!("Failed to get Firewall Rule Name: {}", e);
                    return;
                }
            };

            if name == RULE_NAME {
                count += 1;
            }
        }

        count
    };

    let firewall_rule_count_start = match firewall_rules.get_count() {
        Ok(rule) => rule,
        Err(e) => {
            eprintln!("Failed to get the # of Firewall Rules: {}", e);
            return;
        }
    };

    println!("Removing Firewall Rules...");
    for _ in 0..num_rules {
        if let Err(e) = firewall_rules.remove(RULE_NAME) {
            eprintln!("Failed to remove firewall rule: {}", e);
            return;
        }
    }

    let firewall_rule_count_end = match firewall_rules.get_count() {
        Ok(rule) => rule,
        Err(e) => {
            eprintln!("Failed to get the # of Firewall Rules: {}", e);
            return;
        }
    };

    let rules_removed = firewall_rule_count_start.checked_sub(firewall_rule_count_end);

    if let Some(removed) = rules_removed {
        println!("Removed {} firewall rules", removed);
    }

    if rules_removed != Some(num_rules) {
        eprintln!("Failed to remove the correct # of firewall rules");
    }
}
