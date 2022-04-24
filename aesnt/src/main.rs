use aes::Aes128;
use std::mem::transmute;
//use std::io::prelude::*;
use std::fmt::Write;
use std::io::Write as bWrite;
use chrono::{Timelike, Utc};
//use std::fs::File;
use rayon::prelude::*;
use aes::cipher::{
    BlockDecrypt, KeyInit,
    generic_array::GenericArray 

};

/**
 * Main function
 */
fn main() {

    //get args
    let args: Vec<String> = std::env::args().collect();

    //check args
    if args.len() < 2 {
        usage(None);
    }

    if args[1].eq("-k") {
        keygen();
        std::process::exit(0);
    } 

    if args[1].eq("-d") {
        debug();
        std::process::exit(0);
    }
    //-----------------------------------
    //         FILE IO
    //-----------------------------------
    //let perhaps_mem_file = File::open("starting_key.txt");
    //let mut start_key = String::new();
    //match perhaps_mem_file {
        //Ok(mut mem_file) => {
            //mem_file.read_to_string(&mut start_key).expect("Couldn't read the save file");

        //}
        //Err(_) => usage(Some(String::from("Couldn't open file. Oof. You MUST have a starting key file.")))
    //}
    ////Get rid of trailing newline
    //start_key.pop();

    //Redeclare start_key as a u128 instead of a string
    if args[1].eq("-r") || args[1].eq("-rs") {
        let mut start_guess: u128 = 0;
        let mut end_guess: u128 = 137438953471;

        if args[1].eq("-rs") {
            start_guess = u128::from_str_radix(args[2].as_str(), 10).expect("Couldn't parse starting position as decimal u128");
            end_guess = u128::from_str_radix(args[3].as_str(), 10).expect("Couldn't parse ending position as decimal u128");
        }

        //--------------------------
        //     CHALLENGE DATA
        //--------------------------
        let iv = "A63319C14E9803288D56534C3F19CC81";
        let real_encrypted_block = String::from("9A5AFE9F1014F26F95670D86AB273A823BAD3E1D71F9EB435D8ABDD984FCAC1F2DCD2AE747FE4180438561E14C4020E14F7EDB2ED74089DE1005620F06BF4FFE");

        //-------------------
        // REAL VALUES
        //-------------------

        //let real_encrypted_block = String::from("14B8D1412766A8520BACE4598F8AFAEE7E687A49015FA6F1B914635325A6361B8AD191394EF79CEC4B5A256313632CD48BB4D49F3FA7A917CDF02ECCAA8C4765");
        //let iv = "E898EF8E91F8C9B201E6E29DF87EE152";

        
        //----------------------
        //  DEBUG VALUES
        //----------------------
        //let real_encrypted_block = String::from("6d218b2f7c205ffc37afb825f6cfa372d16659e7cdd049c37920acaf3d85dae9");
        //let real_encrypted_block = String::from("df0d6b13155d343d440ac4a9e8b08148");
        //let real_encrypted_block = String::from("8215ebbf647fb39919fe14bbe17a297c");
        //let iv = "9876543210fedcba9876543210fedcba";

        //Section the IV off the byte string


        //Convert the IV to an unsigned int
        let iv_num: u128 = u128::from_str_radix(iv, 16).expect("IV conversion failed.");

        println!("Starting guess Binary: {:b}\nStarting guess Decimal: {}\n\nEnding guess binary: {:b}\nEnding guess Decimal: {}\n", start_guess, start_guess, end_guess, end_guess);

        dbg!(&iv);
        dbg!(&real_encrypted_block);

        //Tell user we started
        println!("Working...");

        //Spawn a parallel iterator on the possible range 
        //of keys and pass each one to a decrypt manager.
        //Parallelization should be handled automatically
        //on a per system basis.
        (start_guess..end_guess).into_par_iter().for_each(|key| key_splice(iv_num, key, &real_encrypted_block));

        //Create clock for logging finish time
        let now = Utc::now();
        println!("Done at: {:02}:{:02}", now.hour(), now.minute());
    } else {
        usage(Some(String::from("Unknown ARG !")));
    }
}

fn key_splice(iv: u128, guess_num: u128, bytes: &String) {
    //let known = "1100000000000000000000000000000000000000000000000000000000000000000000000000000000000000011";
    //let mut guess_str = String::new();
    //dbg!(&known.len());
    //write!(&mut guess_str, "{:b}", guess_num).expect("Couldn't write to binary buffer");
    //guess_str.push_str(known);
    //dbg!(&guess_str, &guess_str.len());
    //let curren_key = u128::from_str_radix(guess_str.as_str(), 2).expect("Couldn't parse current key as u128");

    let mut curren_key = guess_num << 2; //Make space for 2 1's
    curren_key += 0b11; //Add 2 1's
    curren_key <<= 89; //87 0's + space for 2 1's
    curren_key += 0b11; //Add 2 1's

    //println!("Current key: {:0>128b}", curren_key);
    decrypt_manager(iv, curren_key, bytes);
}

/**
 * Can handle long strings of ciphertext with the IV up front
 * Writes to a file when it finds the answer 
 */
fn decrypt_manager(iv_num: u128, key_num: u128, bytes: &String) {

    //Main plaintext buffer
    let mut plaintext = String::new();    

    //Unsafe code: memory transmutation from u128 to byte array
    //For this case, absolutely worth the simplicity 
    //it offers. All inputs should be checked properly.
    let key_arr: [u8; 16] = unsafe{ transmute( key_num.to_be() ) };
    let mut iv: [u8; 16] = unsafe{ transmute( iv_num.to_be() ) };

    for i in (0..bytes.len()).step_by(32) {
    
        //Extract the current 16 bytes (block) to work on
        let current_bytes = &bytes[i..i+32];

        //Convert the current block to an unsigned int
        let cur_block_num: u128 = u128::from_str_radix(current_bytes, 16)
            .expect("Current Block conversion failed.");
        
        //Transmute the current block into a byte array
        let block_arr: [u8; 16] = unsafe{ transmute( cur_block_num.to_be() ) };

        //Decrypt the block
        let decrypted_block = block_decrypt(iv, key_arr, block_arr);

        //Set up IV for next decryption
        iv = block_arr;

        //Push the block's plaintext into the main buffer
        plaintext.push_str(decrypted_block.as_str());
    }

    if plaintext.chars().all(|c| (c as u8) >= 32 && (c as u8) <= 126) {
        let now = Utc::now();
        let mut filename = String::new();
        write!(&mut filename, "results_from_{:02}{:02}{:02}_hours.txt", now.hour() /*UTC time :)*/, now.minute(), now.second()).expect("Couldn't write time");
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(filename).expect("Couldn't create new results file.");

        let mut output = String::new();
        write!(&mut output, "Plaintext: {}\n\nKey: {:x?}\n\n", plaintext, key_arr).expect("Couldn't write to output buffer");
        file.write_all(output.as_bytes()).expect("Couldn't write to results file");
    }

}

/**
 * Decrypts a single block
 */
fn block_decrypt(iv: [u8; 16], key_arr: [u8; 16], block_arr: [u8; 16]) -> String {
    let key = GenericArray::from_slice(&key_arr).to_owned();
    let mut block = GenericArray::from_slice(&block_arr).to_owned();

    //Create new cipher custom to the current key
    let mechanism = Aes128::new(&key);

    //Uses the Intel AES instructions to decrypt block
    //theoretically in a single 
    mechanism.decrypt_block(&mut block);

    //Bitwise with IV
    //I think compiler will vectorize ?
    for i in 0..16 {
        block[i] = block[i] ^ iv[i];
    }

    //Convert decrypted Hex values to Text
    let mut textblock = vec!();
    block.iter().for_each(|x| textblock.push(*x as char));
    let text: String = textblock.iter().collect();

    text
}


/**
 * Quick and dirty way to generate accurate keys
 * based on their description.
 */
fn keygen() {
    let mut start_key = String::new();
    //push unknown part
    for _i in 0..37 {
        start_key.push_str("0");
    }
    //record length of unknown part
    //push bumped 1
    let starting_key_ones = start_key.len();
    let key_num: u128 = u128::from_str_radix(start_key.as_str(), 2).expect("KeyGen failed keynum");
    //push left over 1's
    start_key.push_str("1");
    start_key.push_str("1");
    //push 0's
    for _i in 0..87 {
        start_key.push_str("0");
    }
    //push trailing 1's
    start_key.push_str("11");
    //printout
    println!("Start Key String: {}\nStart Key Length: {}\nStarting Key Length Up To First 1's: {}",&start_key, start_key.len(), starting_key_ones);
    println!("Start Guess Hex: {:0>32x}\n", key_num);
    let key_num: u128 = u128::from_str_radix(start_key.as_str(), 2).expect("KeyGen failed keynum");
    println!("Start Key Hex: {:0>32x}\n", key_num);
    //--------------------------------------------------- 
    let mut end_key = String::new();
    //push unknown part
    for _i in 0..37 {
        end_key.push_str("1");
    }
    //push bumped 1
    let key_num: u128 = u128::from_str_radix(end_key.as_str(), 2).expect("KeyGen failed keynum");
    //push lefterover 1
    end_key.push_str("1");
    end_key.push_str("1");
    //push 0's
    for _i in 0..87 {
        end_key.push_str("0");
    }
    //push trailing 1's
    end_key.push_str("11");
    //printout
    println!("End Key String: {}\nEnd Key Length: {}",&end_key, end_key.len());
    println!("End Guess Hex: {:0>32x}", key_num);
    let key_num: u128 = u128::from_str_radix(end_key.as_str(), 2).expect("KeyGen failed keynum");
    println!("End Key Hex: {:0>32x}", key_num);
}

/**
 * Debug mode for making sure program runs correctly
 * on a new system
 */
fn debug() {
    let test_iv: u128 = 0x9876543210FEDCBA9876543210FEDCBA;
    let test_key: u128 = 0x000000000000000000000000000000FF;
    let _str_block = String::from("03D735A237D13DEA619C0E810C6BC262");
    let long_str_block = String::from("11B2DC5005FA2C88D65C5DE3583E309B7CC3B1289FB7BC3A3433C1A9FE4FEBD8");
    decrypt_manager(test_iv, test_key, &long_str_block);
}

/**
 * Usage Printer
 */
fn usage(message: Option<String>) {

    let mut m = String::from("Wrong Amount of Arguments.");
    match message {
       Some(s) => m = s,
       None => {}
    }

    println!("{}\n\nUsage:\n\taesnt -k\tDisplays Key Info\n\taesnt -r\tRuns Cracker On Whole Key Range\n\taesnt -d\tDebug Mode to Test on New Machines\n\taesnt -rs <START> <END>\tRun the Cracker on a specific guess range", m);
    std::process::exit(1);
}