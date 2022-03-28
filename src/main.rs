//extern crate linux_embedded_hal as hal;
extern crate sx127x_lora;

// LORA MODULE

use rppal::gpio::Gpio;
use rppal::spi::{Bus, Mode, Segment, SlaveSelect, Spi};
use rppal::hal::Delay;

/*use hal::spidev::{self, SpidevOptions};
use hal::{Pin, Spidev};
use hal::sysfs_gpio::Direction;
use hal::Delay;
*/
use x25519_dalek_ng::{PublicKey, SharedSecret, StaticSecret};

use hkdf::Hkdf;
use rand::{rngs::StdRng, Rng, SeedableRng};
use rand_core::OsRng;
use std::sync::mpsc;
use std::thread;

// ECHOC

use oscore::edhoc::{
    error::{OwnError, OwnOrPeerError},
    PartyI, PartyR,
};

const SUITE_I: isize = 3;
const METHOD_TYPE_I: isize = 0;

// TWORATCHET

use twoRatchet::ratchfuncs::state;

// LORAMODULE

const LORA_CS_PIN: u64 = 8;
const LORA_RESET_PIN: u64 = 21;
const FREQUENCY: i64 = 915;

fn main() {
    /*let mut spi = Spidev::open("/dev/spidev0.0").unwrap();
    let options = SpidevOptions::new()
        .bits_per_word(8)
        .max_speed_hz(20_000) // muligvis decrease
        .mode(spidev::SPI_MODE_0)
        .build();
    spi.configure(&options).unwrap();


    let cs = Pin::new(LORA_CS_PIN);
    cs.unwrap(); //.unwrap();
    //cs.set_direction(Direction::Out).unwrap();

    let reset = Pin::new(LORA_RESET_PIN);
    reset.export().unwrap();
    reset.set_direction(Direction::Out).unwrap();
*/

    let spi = Spi::new(Bus::Spi0, SlaveSelect::Ss0, 8_000_000, Mode::Mode0).unwrap();

    let gpio = Gpio::new().unwrap();

    let cs = gpio.get(8).unwrap().into_output();
    let reset = gpio.get(21).unwrap().into_output();

    let mut lora =  
    sx127x_lora::LoRa::new(spi, cs, reset, FREQUENCY, Delay).unwrap();

    //match lora {
    //    Ok(_) => println!("lora succes"),
    //    Err(x) => println!("bad shiet {:?}", x),
    //};

    //lora.set_tx_power(17, 1); //Using PA_BOOST. See your board for correct pin.

    let message = "Hello, world!";
    let mut buffer = [0; 255];
    for (i, c) in message.chars().enumerate() {
        buffer[i] = c as u8;
    }

    let transmit = lora.transmit_payload(buffer, message.len());
    match transmit {
        Ok(packet_size) => println!("Sent packet with size: {:?}", packet_size),
        Err(_) => println!("Error"),
    }
    /*
    edhoc_fun();
    //lora_ratchet_fun();
    */
}
/*
fn edhoc_fun() {
    
    /*
    Parti I generate message 1
    */

    let i_static_priv: StaticSecret = StaticSecret::new(OsRng);
    let i_static_pub = PublicKey::from(&i_static_priv);

    // Party U ----------------------------------------------------------------
    // "Generate" an ECDH key pair (this is static, but MUST be ephemeral)
    // The ECDH private key used by U
    let mut r: StdRng = StdRng::from_entropy();
    let i_priv = r.gen::<[u8; 32]>();

    // Choose a connection identifier
    let i_c_i = [0x1].to_vec();

    let i_kid = [0xA2].to_vec();
    let msg1_sender = PartyI::new(i_c_i, i_priv, i_static_priv, i_static_pub, i_kid);

    // type = 1 would be the case in CoAP, where party U can correlate
    // message_1 and message_2 with the token
    let (msg1_bytes, msg2_receiver) =
        // If an error happens here, we just abort. No need to send a message,
        // since the protocol hasn't started yet.
        msg1_sender.generate_message_1(METHOD_TYPE_I, SUITE_I).unwrap();

    //  let msg_1_struct : Message1= util::deserialize_message_1(&msg1_bytes).unwrap();

    /*
    /// Party R handle message 1
     */

    let r_static_priv: StaticSecret = StaticSecret::new(OsRng);
    let r_static_pub = PublicKey::from(&r_static_priv);

    let r_kid = [0xA3].to_vec();

    // create keying material

    let mut r2: StdRng = StdRng::from_entropy();
    let r_priv = r2.gen::<[u8; 32]>();

    let msg1_receiver = PartyR::new(r_priv, r_static_priv, r_static_pub, r_kid);

    let msg2_sender = match msg1_receiver.handle_message_1(msg1_bytes) {
        Err(OwnError(b)) => {
            panic!("{:?}", b)
        }
        Ok(val) => val,
    };

    // generated shared secret for responder:
    // println!("{:?}", msg2_sender.0.shared_secret.to_bytes());

    /*
    Responder gør sig klar til at lave message 2.
    */

    let (msg2_bytes, msg3_receiver) = match msg2_sender.generate_message_2() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        }
        Ok(val) => val,
    };

    /*///////////////////////////////////////////////////////////////////////////
    /// Initiator receiving and handling message 2, and then generating message 3, and the rck/sck
    ///////////////////////////////////////////////////////////////////// */

    // unpacking message, and getting kid, which we in a realworld situation would use to lookup our key
    let (r_kid, msg2_verifier) = match msg2_receiver.unpack_message_2_return_kid(msg2_bytes) {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Error during  {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        }
        Ok(val) => val,
    };

    println!("initiator unpacked responders kid: {:?}", r_kid);

    let msg3_sender = match msg2_verifier.verify_message_2(&r_static_pub.as_bytes().to_vec()) {
        Err(OwnError(b)) => panic!("Send these bytes: {:?}", &b),
        Ok(val) => val,
    };

    let (msg4_receiver_verifier, msg3_bytes) = match msg3_sender.generate_message_3() {
        Err(OwnError(b)) => panic!("Send these bytes: {}", hexstring(&b)),
        Ok(val) => val,
    };

    /*///////////////////////////////////////////////////////////////////////////
    /// Responder receiving and handling message 3, and generating message4 and sck rck
    ///////////////////////////////////////////////////////////////////// */

    let tup3 = msg3_receiver.handle_message_3(msg3_bytes, &i_static_pub.as_bytes().to_vec());

    let (msg4sender, r_sck, r_rck) = match tup3 {
        Ok(v) => v,
        Err(e) => panic!("panicking in handling message 3 {}", e),
    };

    let msg4_bytes = match msg4sender.generate_message_4() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        }
        Ok(val) => val,
    };

    /*///////////////////////////////////////////////////////////////////////////
    /// Initiator receiving and handling message 4, and generati  sck and rck. Then all is done
    ///////////////////////////////////////////////////////////////////// */

    let (i_sck, i_rck) = match msg4_receiver_verifier.receive_message_4(msg4_bytes) {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        }
        Ok(val) => val,
    };

    println!("Initiator completed handshake and made chan keys");

    println!("sck {:?}", i_sck);
    println!("rck {:?}", i_rck);
    println!("Responder completed handshake and made chan keys");

    println!("sck {:?}", r_sck);
    println!("rck {:?}", r_rck);
}

/*fn lora_ratchet_fun() {
    let sk = [
        16, 8, 7, 78, 159, 104, 210, 58, 89, 216, 177, 79, 10, 252, 39, 141, 8, 160, 148, 36, 29,
        68, 31, 49, 89, 67, 233, 53, 16, 210, 28, 207,
    ];
    let downlink = [
        0, 171, 247, 26, 19, 92, 119, 193, 156, 216, 49, 89, 90, 174, 165, 23, 124, 247, 30, 79,
        73, 164, 55, 63, 178, 39, 228, 26, 180, 224, 173, 104,
    ];
    let uplink = [
        218, 132, 151, 66, 151, 72, 196, 104, 152, 13, 117, 94, 224, 7, 231, 216, 62, 155, 135, 52,
        59, 100, 217, 236, 115, 100, 161, 95, 8, 146, 123, 146,
    ];

    let ad_r = &[1];
    let ad_i = &[2];

    // iFirst the two parties initialize, where I outputs her pk

    // initialising one party for the ratchet
    let (mut i_ratchet, dhr_req) =
        state::init_i(sk, downlink, uplink, ad_i.to_vec(), ad_r.to_vec());


    //let mut r_ratchet = state::init_r(sk, uplink, downlink, ad_i.to_vec(), ad_r.to_vec());

    // r recevies the pk of i, ratcets, and sends it's own pk
    /*
        let newout = match  r_ratchet.r_receive(dhr_req) {
            Some((x,b)) => x,
            None => [0].to_vec(), // in this case, do nothing
        };
        // i receives the pk of r, and makes it's own ratchet
        let _ratchdone =  i_ratchet.i_receive(newout);
        // Now we are both fully initialized with a ratchet, and I should be able to encrypt something
        let enclost = i_ratchet.ratchet_encrypt(&b"lost".to_vec(), ad_i);
    */

    // encrypt besked
    let enc0 = i_ratchet.ratchet_encrypt(&b"lost".to_vec(), ad_i);


    // decrypt
    let dec0 = match r_ratchet.r_receive(&enc0) {
        Some((x, b)) => x,
        None => [0].to_vec(),
    };

    assert_eq!(dec0, b"lost".to_vec());

    let encr = r_ratchet.ratchet_encrypt(&b"downlink".to_vec(), ad_r);

    let decr = match i_ratchet.i_receive(encr) {
        Some((x, b)) => x,
        None => [0].to_vec(), // do nothing
    };

    // now I wants to ratchet again

    let newpk = i_ratchet.i_initiate_ratch();

    // R recevies dhr res
    let dh_ack = match r_ratchet.r_receive(&newpk) {
        Some((x, b)) => x,
        None => [0].to_vec(), // in this case, do nothing
    };
    // and responds with a dhr ack, which i receives
    let _ratchdone = i_ratchet.i_receive(dh_ack);

    let lostmsg = i_ratchet.ratchet_encrypt(&b"lost".to_vec(), ad_i);
    let msg3 = i_ratchet.ratchet_encrypt(&b"msg3".to_vec(), ad_i);

    let dec0 = match r_ratchet.r_receive(&msg3) {
        Some((x, b)) => x,
        None => [0].to_vec(),
    };

    assert_eq!(b"msg3".to_vec(), dec0);
    let declost = match r_ratchet.r_receive(&lostmsg) {
        Some((x, b)) => x,
        None => [0].to_vec(),
    };
    assert_eq!(b"msg3".to_vec(), dec0);
}

fn loraratchet_initialize(){

}*/

fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}
*/