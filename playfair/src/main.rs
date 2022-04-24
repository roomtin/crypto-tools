use std::env;
use std::collections::HashMap;
use std::collections::HashSet;

/**
 * Tool for helping break a playfair cipher from
 * known plaintext. This tool can return useful 
 * information about pairs of letters or single 
 * letters to help a human build the original
 * playfair table used to encrypt.
 * 
 * Note: This tool was built hastily because it needed to be
 * used as soon as possible, so there might be some less 
 * than good practices in the code, however to my knowledge 
 * it does function correctly because I was able to use it
 * to break a playfair cipher.
 */

fn main() {
    //Args
    let args: Vec<String> = env::args().collect();

    //arg check
    if &args.len() > &3 || &args.len() < &2 {
        println!("Wrong amount of args.\n");
        println!("Usage: \n\tplayfair <mode> [letter(s)]\n\n\tModes: \"s\" for lookup and \"d\" for dump all pairs\n\t\"l\" for lookup single letter stats, and \"a\" for alphabet stats.)");
        std::process::exit(1);
    }
    //Auto mode
    if args[1].eq("a") {
        let alphabet = splitstring(String::from("abcdefghiklmnopqrstuvwxyz"));

        let mut amounts = vec![];

        for i in 0..alphabet.len() {
            amounts.push(single_stats(&alphabet[i]));
        }

        dbg!(amounts);
    }


    //Lookup the relative sets of a specific letter
    if args[1].eq("l") {
        let _unused_value = single_stats(&args[2]);

    } else {
        //Real work:
        let mut lookup: HashMap<String, String> = HashMap::new();
        let p0 = String::from("wearethatfarfromaturnkeytotalitarianstatez");
        let c0 = String::from("vntnrlfiagtngnpotibubfuvapitacitutnfpctibv");

        pushall(&mut lookup, breakstring(p0), breakstring(c0));

        let p1 = String::from(
            "neverunderestimatethetimeandexpenseyouropxponentwilxltaketobreakyourcode",
        );
        let c1 = String::from(
            "rnldubefnubmicollrigrllqnlefrvmrbouvqnnpxtqprnrayatvaicfrlsnuncfwqbuasmd",
        );

        pushall(&mut lookup, breakstring(p1), breakstring(c1));

        let p2 = String::from("cryptographyisbestlefttothoseofaparanoidmindsetz");
        let c2 = String::from("tbxqappgtoqicqenpcedgaapigpmnmonotntfwlhqlefmbcx");

        pushall(&mut lookup, breakstring(p2), breakstring(c2));

        let p3 = String::from("cypherpunkswritecodecypherpunkspublishtheircodez");
        let c3 = String::from("izqgnuqrbfozutlrasmdizqgnuqrbfmqbeacqkigulbtmfbv");

        pushall(&mut lookup, breakstring(p3), breakstring(c3));

        let p4 = String::from("wearelegionwedonotforgivewedonotforgetexpectus");
        let c4 = String::from("vntnderdaqfadmwfpaowgplynvdmwfpaowgprlrvmrlibq");

        pushall(&mut lookup, breakstring(p4), breakstring(c4));

        //Query
        if args[1].eq("s") {
            let query: Option<&String> = lookup.get(&args[2]);
            match query {
                Some(s) => {
                    println!("\n\r\t>>>{}", s);
                }
                None => {
                    println!("\n\r\t\"{}\" isn't in the HashMap.", &args[2])
                }
            }
        }
        if args[1].eq("d") {
            dbg!(&lookup);
            dbg!(lookup.len());
        }
    }
}
/**
 * Finds and prints the known relations of a particular letter.
 * Returns a tuple so that the automatic mode can print the size
 * of the relation sets for every letter, otherwise the data isn't
 * needed.
 */
fn single_stats(target: &str) -> (&str, usize, usize) {
    //Real work:
    let mut plain_to_cipher: HashSet<String> = HashSet::new();
    let mut cipher_to_plain: HashSet<String> = HashSet::new();
    let p0 = String::from("wearethatfarfromaturnkeytotalitarianstatez");
    let c0 = String::from("vntnrlfiagtngnpotibubfuvapitacitutnfpctibv");

    find_pairs(
        &target,
        &mut plain_to_cipher,
        &mut cipher_to_plain,
        splitstring(p0),
        splitstring(c0),
    );

    let p1 =
        String::from("neverunderestimatethetimeandexpenseyouropxponentwilxltaketobreakyourcode");
    let c1 =
        String::from("rnldubefnubmicollrigrllqnlefrvmrbouvqnnpxtqprnrayatvaicfrlsnuncfwqbuasmd");

    find_pairs(
        &target,
        &mut plain_to_cipher,
        &mut cipher_to_plain,
        splitstring(p1),
        splitstring(c1),
    );

    let p2 = String::from("cryptographyisbestlefttothoseofaparanoidmindsetz");
    let c2 = String::from("tbxqappgtoqicqenpcedgaapigpmnmonotntfwlhqlefmbcx");

    find_pairs(
        &target,
        &mut plain_to_cipher,
        &mut cipher_to_plain,
        splitstring(p2),
        splitstring(c2),
    );

    let p3 = String::from("cypherpunkswritecodecypherpunkspublishtheircodez");
    let c3 = String::from("izqgnuqrbfozutlrasmdizqgnuqrbfmqbeacqkigulbtmfbv");

    find_pairs(
        &target,
        &mut plain_to_cipher,
        &mut cipher_to_plain,
        splitstring(p3),
        splitstring(c3),
    );

    let p4 = String::from("wearelegionwedonotforgivewedonotforgetexpectus");
    let c4 = String::from("vntnderdaqfadmwfpaowgplynvdmwfpaowgprlrvmrlibq");

    find_pairs(
        &target,
        &mut plain_to_cipher,
        &mut cipher_to_plain,
        splitstring(p4),
        splitstring(c4),
    );

    println!("\"{}\" can be encrypted as: {:?}", &target, plain_to_cipher);
    println!("-------AND--------");
    println!("\"{}\" can be decrypted as: {:?}", &target, cipher_to_plain);

    //Return a tuple so that the automatic mode has this data, 
    //but elsewhere it's not needed
    (target, plain_to_cipher.len(), cipher_to_plain.len())
}
/**
 * Finds all the possible relations of a letter and pushes results
 * into the respective HashSets. Hashsets are used just for the
 * side effect they have of only retaining 1 copy of redundant
 * entries.
 */
fn find_pairs(
    target: &str,
    plain_to_cipher: &mut HashSet<String>,
    cipher_to_plain: &mut HashSet<String>,
    plain: Vec<String>,
    cipher: Vec<String>,
) {
    for i in 0..plain.len() {
        if plain[i].eq(target) {
            let _unused_value = plain_to_cipher.insert(cipher[i].clone());
        }
        if cipher[i].eq(target) {
            let _unused_value = cipher_to_plain.insert(plain[i].clone());
        }
    }
}

//Pushes all the pairs into the map
fn pushall(map: &mut HashMap<String, String>, plain: Vec<String>, cipher: Vec<String>) {
    for i in 0..plain.len() {
        map.insert(cipher[i].clone(), plain[i].clone());
    }
}
/**
 * Splits a string into a vector of strings.
 * Realized later that .chars() is the better
 * way to do this.
 */
fn splitstring(s: String) -> Vec<String> {
    let mut splitted: Vec<String> = s.split("").map(|x| x.to_string()).collect();
    //remove the empty strings at 0 and the end. They're artifacts of .split
    splitted.pop();
    splitted.remove(0);
    splitted
}

//Breaks all the strings down into vecs of char pairs.
fn breakstring(s: String) -> Vec<String> {
    let mut fractured: Vec<String> = vec![];
    for i in (0..s.as_bytes().len()).step_by(2) {
        fractured.push(s[i..i + 2].to_string());
    }
    fractured
}
