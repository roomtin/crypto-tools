use std::env;
use std::fmt::Write;
use std::fs::File;
use std::io::Write as bWrite;
use std::io::prelude::*; //Read to string is in here


fn main() {
    //Args
    let args: Vec<String> = env::args().collect();
    

    //arg check
    if &args.len() < &2 || &args.len() > &4 {
        println!("Wrong amount of args.\n");
        println!("Usage: \n\tswap a <cipher letter> <plain letter> (ADD PAIR)\n\tswap r <plaintext letter> (REMOVE PAIR)\n\tswap s (SHOW PAIRS)\n\tswap p (PRINT PLAINTEXT PROGRESS)");
        std::process::exit(1);
    }

    //add mode
    if args[1].eq("a") {
        addmode(&args)
    }

    if args[1].eq("r") {
        removemode(&args)
    }

    if args[1].eq("s") {
        showswaps()
    }

    //print mode, read swaps from file and apply to printout of ciphertext
    if args[1].eq("p") {
        printmode()
    }
}

pub fn removemode(args: &Vec<String>) {
    let mut swap_file = File::open("swap_file.txt").expect("Can't find swapfile printmode");
    let mut buf = String::new();
    swap_file.read_to_string(&mut buf).expect("swap read to string failed in print");
    //split the file up into an array of bytestrings
    let mut swaps = buf.split("\n").collect::<Vec<&str>>();
    
    //removing the trailing empty string
    let _garbage = &swaps.pop();
    let removed: &str;
    
    //switch the arg slice to upper case for finding proper remove index
    let to_remove: &str = &String::from(args[2].clone()).to_uppercase()[0..1];

    let possible_index: Option<usize> = swaps.iter().position(|x| x.contains(to_remove));
    match possible_index {
        Some(index) => {removed = swaps.remove(index);}
        None => {
            println!("We currently don't know what the ciphertext for {} is.\nInvalid remove.", to_remove);
            std::process::exit(1);
        }
    }

    std::fs::remove_file("swap_file.txt").expect("Failed to delete old swap file.");
    let mut new_swap_file = std::fs::OpenOptions::new().create(true).append(true).open("swap_file.txt").expect("Couldn't create new swap file.");
    //add a newline to each stack string for proper writing to file
    let mut write_buf: Vec<String> = swaps.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    for entry in &mut write_buf {
        entry.push_str(&"\n");
    }
    for line in write_buf {
        new_swap_file.write_all(line.as_bytes()).expect("Couldn't write to new swap file.");
    }
    println!("Removed: {}", removed);


}

pub fn showswaps() {
    let mut swap_file = File::open("swap_file.txt").expect("Can't find swapfile printmode");
    let mut buf = String::new();
    swap_file.read_to_string(&mut buf).expect("swap read to string failed in print");
    //split the file up into an array of bytestrings and then convert all of the byte strings to actual string types
    let mut swaps = buf.split("\n").collect::<Vec<&str>>();
    
    //removing the trailing empty string
    let _garbage = &swaps.pop();
    let letters = vec!("A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z");
    let mut cryptletters: Vec<&str> = letters.clone();

    for i in 0..letters.len() {
        let possible_index: Option<usize> = swaps.iter().position(|x| x.contains(letters[i]));
        if possible_index.is_some() {
            cryptletters[i] = &swaps.iter().nth(possible_index.unwrap()).unwrap()[0..1];
        }
        else {
            cryptletters[i] = " "
        }
    }    

    println!("\nTop line is plaintext, bottom line is ciphertext.\nHere are the current swaps:\n");
    letters.iter().for_each(|x| print!("{} ", x.to_string().to_lowercase()));
    println!();
    for _i in 0..26 {
        print!("| ");
    }
    println!();
    cryptletters.iter().for_each(|x| print!("{} ", x));
    println!();

}


pub fn addmode(args: &Vec<String>) {
    let mut swap_file = File::open("swap_file.txt").expect("Can't find swapfile printmode");
    let mut buf = String::new();
    swap_file.read_to_string(&mut buf).expect("swap read to string failed in print");
    //split the file up into an array of bytestrings
    let mut swaps = buf.split("\n").collect::<Vec<&str>>();
    
    //removing the trailing empty string
    let _garbage = &swaps.pop();
    let _added: &str;
    let plain_to_add: &str = &String::from(args[3].clone()).to_uppercase()[0..1];
    let crypt_to_add: &str = &String::from(args[2].clone())[0..1];

    let possible_index_plain: Option<usize> = swaps.iter().position(|x| x.contains(plain_to_add));
    match possible_index_plain {
        Some(_index) => {
            println!("We are already using the plaintext letter: {}\nInvalid add.\nRemove the binding first if you want to change it.", plain_to_add);
            std::process::exit(1);
        }
        None => {}
    }
    let possible_index_crypt: Option<usize> = swaps.iter().position(|x| x.contains(crypt_to_add));
    match possible_index_crypt {
        Some(_crypt_index) => {
            println!("We are already using the ciphertext letter: {}\nInvalid add.\nRemove the binding first if you want to change it.", crypt_to_add);
            std::process::exit(1);
        }
        None => {}
    }

    //Buffer string and file
    let mut swap_string: String = String::new();
    //write to string
    write!(&mut swap_string, "{}>>>{}\n", args[2], args[3].to_uppercase()).expect("String write failed at 1!");
    //save to file for persistance
    let mut swap_file = std::fs::OpenOptions::new().create(false).append(true).open("swap_file.txt").expect("Swap file needs to exist first.");
    swap_file.write_all(swap_string.as_bytes()).expect("Failed to write swap file.");

    println!("Added: {}", swap_string);


}

pub fn printmode() {
    let mut swap_file = File::open("swap_file.txt").expect("Can't find swapfile printmode");
    let mut buf = String::new();
    swap_file.read_to_string(&mut buf).expect("swap read to string failed in print");
    //split the file up into an array of bytestrings and then convert all of the byte strings to actual string types
    let mut swaps = buf.split("\n").collect::<Vec<&str>>().into_iter().map(|x| x.to_string()).collect::<Vec<String>>();
    
    //removing the trailing empty string
    let _garbage = &swaps.pop();

    //Open original ciphertext file and read into string
    let mut cipherfile = File::open("ciphertext.txt").expect("ciphertext.txt could not be found.");
    let mut ciphertext = String::new();
    let mut plaintext = String::new();

    //make string for possible plaintext
    cipherfile.read_to_string(&mut ciphertext).expect("converting file to string panicked");

    //apply all the swaps

    //ignore all the .chars.nth.unwrap stuff, .replace takes weird stuff
    //as the arguments for more flexibility with more complex replacements
    // and the result is simple stuff looks more complicated than it is.
    // All this does is replace all the occurances of the first arg with the second arg
    for swap in swaps {
        plaintext = ciphertext.replace(swap.chars().nth(0).unwrap(), &swap.chars().nth(4).unwrap().to_string());
        ciphertext = plaintext.clone();
    }

    print!("{}", plaintext);
}