use std::io::{self, Write};

pub fn display_message(sender: &str, msg: &str) {
    println!("\n[{}]: {}", sender, msg);
}

pub fn show_fingerprint(fingerprint: &str) {
    println!("\n🔐 Identity Fingerprint: {}", fingerprint);
}

pub fn show_system_message(msg: &str) {
    println!("\nℹ️  {}", msg);
}

pub fn get_user_input(prompt: &str) -> String {
    print!("{} ", prompt);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

pub fn show_menu() {
    println!("\n--- ReDoor Secure Chat ---");
    println!("1. Generate Identity");
    println!("2. Start Chat Session (requires peer fingerprint confirmation)");
    println!("3. Send Message");
    println!("4. Receive Message (Simulate)");
    println!("5. Exit");
    print!("Select option: ");
    io::stdout().flush().unwrap();
}
