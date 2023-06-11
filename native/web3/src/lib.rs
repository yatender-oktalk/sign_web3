use hex::FromHex;
use rustler::{Encoder, Env, Error, NifResult, Term};
use std::borrow::Borrow;
use std::collections::HashMap;
use web3::api::accounts::accounts_signing::Transaction;
use web3::types::{Address, Bytes, CallRequest, SignedTransaction, TransactionParameters, U64};
use ethereum_types::U256;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use rand::rngs::OsRng;
use serde_json::json;
use web3::ethabi::{ethereum_types, ParamType, Token};
use web3::ethabi::param_type::Reader;
use web3::ethabi;
use rustler::types::tuple::make_tuple;
use web3::ethabi::ethereum_types::Public;
use parity_crypto::publickey;
use std::str::FromStr;


const EIP1559_TX_ID: u64 = 2;

// #[macro_export]
macro_rules! err {
    ( $( $x:expr ),* ) => {
        {
            $(
                Err(Error::Term(Box::new($x)))
            )*
        }
    };
}
macro_rules! error {
    ( $( $x:expr ),* ) => {
        {
            $(
                Error::Term(Box::new($x))
            )*
        }
    };
}

#[rustler::nif(schedule = "DirtyCpu")]
fn decode_result<'a>(
    env: Env<'a>,
    term_response: Term,
    term_param_types: Term,
) -> NifResult<Term<'a>> {
    let prefixed_encoded_response = term_response
        .decode::<&str>()
        .or(err!("could not decode response"))?;

    let encoded_response = prefixed_encoded_response
        .strip_prefix("0x")
        .ok_or(error!("to field needs to start with 0x"))?;

    let string_param_types = term_param_types
        .decode::<Vec<&str>>()
        .or(err!("could not decode response type"))?;

    let params_count = string_param_types.len();
    let mut param_types = Vec::with_capacity(params_count);

    for pt in string_param_types {
        param_types.push(Reader::read(pt)
            .or(err!("could not decode the type as any known ParamType"))?)
    }

    // param_types.get(0).unwrap()
    let tokens = ethabi::decode(param_types.as_slice(), hex::decode( encoded_response).or(err!(""))?.as_slice())
        .or(err!("could not decode abi params"))?;
    
    let mut terms  = Vec::with_capacity(params_count);
    for token in tokens {terms.push(render_token(env, &token)?)}

    Ok(make_tuple(env,terms.as_slice()).encode(env))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn encode_call<'a>(
    env: Env<'a>,
    term_call: Term,
) -> NifResult<Term<'a>> {
    let call = term_call.decode::<HashMap<String, Term>>()
        .or(err!("could not decode params as map<String,Term>"))?;

    let string_to = call.get("to")
        .ok_or(error!("to field is missing"))?
        .decode::<String>()
        .or(err!("could not decode to field"))?;

    let to = Some(Address::from(<[u8; 20]>::from_hex(string_to.strip_prefix("0x")
        .ok_or(error!("to field needs to start with 0x"))?)
        .or(err!("to field has the wrong format"))?
        .borrow()));

    let (string_fun, string_param_types, term_params) = call.get("fav")
        .ok_or(error!("fav field is missing"))?
        .decode::<(&str,Vec<&str>,Vec<Term>)>()
        .or(err!("could not decode fav field"))?;

    let params_count = string_param_types.len();
    if term_params.len() != params_count {return err!("signature param_types count different from params count")}

    let mut param_types = Vec::with_capacity(params_count);

    for pt in string_param_types {
        param_types.push(Reader::read(pt)
            .or(err!("could not decode the type as any known ParamType"))?)
    }

    let signature = ethabi::short_signature(string_fun, param_types.as_slice()).to_vec();

    let mut tokens = Vec::with_capacity(params_count);
    for (x,y) in term_params.iter().zip(param_types.iter()) { tokens.push(to_token(x,y)?) }
    let encoded = ethabi::encode(tokens.as_slice());

    let call_request = CallRequest {
        to,
        data: Some(Bytes(signature.into_iter().chain(encoded.into_iter()).collect())),
        ..CallRequest::default()
    };

    // Ok(json!(call_request).to_string().encode(env))
    Ok(json!(call_request.data)
        .as_str()
        .ok_or(error!("could not parse json response as string"))?
        .encode(env))
}

#[rustler::nif(schedule = "DirtyCpu")]
pub fn gen_keys(env: Env) -> NifResult<Term> {

    let curve = Secp256k1::new();
    let mut rng = OsRng::new().unwrap();
    let (sk, pk) = curve.generate_keypair(&mut rng);

    let address = publickey::public_to_address(&Public::from_slice(&pk.serialize_uncompressed()[1..65]));

    Ok(make_tuple(env ,&[sk.serialize_secret().encode(env), format!("0x{:x}", address).encode(env)]))

}

#[rustler::nif(schedule = "DirtyCpu")]
pub fn to_addr<'a>(env: Env<'a>, term_sk: Term,) -> NifResult<Term<'a>> {

    let curve = Secp256k1::new();
    let sk = &SecretKey::from_slice(term_sk.decode::<Vec<u8>>()
        .or(err!("private key should be binary"))?
        .as_slice())
        .or(err!("could not decode key as a secret key"))?;

    let pk = PublicKey::from_secret_key(&curve, &sk);

    let address = publickey::public_to_address(&Public::from_slice(&pk.serialize_uncompressed()[1..65]));

    Ok(format!("0x{:x}", address).encode(env))

}

#[rustler::nif(schedule = "DirtyCpu")]
fn sign_tx<'a>(
    env: Env<'a>,
    term_sk: Term,
    term_tx: Term,
    term_chain_id: Term,
) -> NifResult<Term<'a>> {
    let tx = term_tx.decode::<HashMap<String, Term>>()
        .or(err!("could not decode params as map<String,Term>"))?;

    let to = Some(Address::from_str(
        tx.get("to")
        .ok_or(error!("to field is missing"))?
        .decode::<&str>()
        .or(err!("could not decode to field into &str"))?)
        .or(err!("could not convert to field into Address"))?);

    let gas_price = U256::from_str(tx.get("gas_price")
        .ok_or(error!("gas_price field is missing"))?
        .decode::<&str>()
        .or(err!("could not decode gas_price field into &str"))?)
        .or(err!("could not convert gas_price field into U256"))?;

    let nonce = U256::from_str(tx.get("nonce")
        .ok_or(error!("nonce field is missing"))?
        .decode::<&str>()
        .or(err!("could not decode nonce field into &str"))?)
        .or(err!("could not convert nonce field into U256"))?;

    let (string_fun, string_param_types, term_params) = tx.get("fav")
        .ok_or(error!("fav field is missing"))?
        .decode::<(&str,Vec<&str>,Vec<Term>)>()
        .or(err!("could not decode fav field"))?;

    let sk = &SecretKey::from_slice(term_sk.decode::<Vec<u8>>()
        .or(err!("private key should be binary"))?
        .as_slice())
        .or(err!("could not decode key as a secret key"))?;

    let chain_id = term_chain_id.decode::<u64>()
        .or(err!("could not decode chain_id as u64"))?;

    let params_count = string_param_types.len();
    if term_params.len() != params_count {return err!("signature param_types count different from params count")}

    let mut param_types = Vec::with_capacity(params_count);
    
    for pt in string_param_types {
        param_types.push(Reader::read(pt)
            .or(err!("could not decode the type as any known ParamType"))?)
    }

    let signature = ethabi::short_signature(string_fun, param_types.as_slice()).to_vec();

    let mut tokens = Vec::with_capacity(params_count);
    for (x,y) in term_params.iter().zip(param_types.iter()) { tokens.push(to_token(x,y)?) }
    let encoded = ethabi::encode(tokens.as_slice());

    let tx = TransactionParameters {
        ..Default::default()
    };

    let max_priority_fee_per_gas = match tx.transaction_type {
        Some(tx_type) if tx_type == U64::from(EIP1559_TX_ID) => {
            tx.max_priority_fee_per_gas.unwrap_or(gas_price)
        }
        _ => gas_price,
    };

    let tx = Transaction {
        to,
        nonce,
        gas: tx.gas,
        gas_price,
        value: tx.value,
        data: Bytes(signature.into_iter().chain(encoded.into_iter()).collect()).0,
        transaction_type: tx.transaction_type,
        access_list: tx.access_list.unwrap_or_default(),
        max_priority_fee_per_gas,
    };
    // println!("{:?}", tx);

    let signed :SignedTransaction = tx.sign(sk, chain_id);

    Ok(hex::encode(signed.raw_transaction.0).encode(env))
}

rustler::init!("Elixir.SignWeb3", [sign_tx, gen_keys, encode_call, decode_result, to_addr]);

fn to_token(v: &Term , pt: &ParamType) -> NifResult<Token> {
    match pt {  // == ParamType::Bool && v.is_boolean() {
        ParamType::Bool => {
            let bool = v.decode::<bool>()
                .or(err!("could not decode the routing_table_id"))?;

            Ok(Token::Bool(bool))
        },
        ParamType::Address => {
            let to_address = v.decode::<String>()
                .or(err!("could not decode to String"))?;

            let address = Address::from(<[u8; 20]>::from_hex(
                to_address.strip_prefix("0x")
                    .unwrap()).unwrap().borrow());

            Ok(Token::Address(address))
        },
        ParamType::Bytes => {
            let bytes = v.decode::<Vec<u8>>()
                .or(err!("could not decode to Vec<u8>"))?;

            Ok(Token::Bytes(bytes))
        },
        ParamType::FixedBytes(_) => {
            let fixed_bytes = v.decode::<Vec<u8>>()
                .or(err!("could not decode to Vec<u8>"))?;

            Ok(Token::FixedBytes(fixed_bytes))
        },
        ParamType::Uint(_) => {
            let uint = U256::from_dec_str(v.decode::<&str>()
                .or(err!("could not decode to uint256"))?)
                .or(err!("uint256 param has wrong format"))?;

            Ok(Token::Uint(uint))
        },
        ParamType::Int(_) => {
            let int = U256::from_dec_str(v.decode::<&str>()
                .or(err!("could not decode to int"))?)
                .or(err!("int param has wrong format"))?;

            Ok(Token::Int(int))
        },
        ParamType::String => {
            let string = v.decode::<String>()
                .or(err!("could not decode to String"))?;

            Ok(Token::String(string))
        },
        ParamType::Array(subtype) => {
            let tokens = v.decode::<Vec<Term>>()
                .or(err!("could not decode array to Vec<Term>"))?;

            let mut subtokens = Vec::new();
            for token in tokens {
                // in Dom's code &subtype.as_ref().clone() was used
                match to_token(&token, &subtype) {
                    Ok(subtoken) => subtokens.push(subtoken),
                    Err(e) => return Err(e)
                }
            }
            Ok(Token::Array(subtokens))
        },
        ParamType::FixedArray(subtype, _) => {
            let tokens = v.decode::<Vec<Term>>()
                .or(err!("could not decode fixed_array to Vec<Term>"))?;

            let mut subtokens = Vec::new();
            for token in tokens {
                match to_token(&token, &subtype) {
                    Ok(subtoken) => subtokens.push(subtoken),
                    Err(e) => return Err(e)
                }
            }
            Ok(Token::FixedArray(subtokens))
        },
        ParamType::Tuple(param_types) => {
            let tokens = v.decode::<Vec<Term>>()
                .or(err!("could not decode tuple to Vec<Term>"))?;

            let zip = tokens.iter().zip(param_types.iter());

            let mut subtokens = Vec::new();
            for (token, param_type) in zip {
                match to_token(&token, &param_type) {
                    Ok(subtoken) => subtokens.push(subtoken),
                    Err(e) => return Err(e)
                }
            }

            Ok(Token::Tuple(subtokens))
        }
    }
}

fn render_token<'a>(env: Env<'a>, token : &Token) -> NifResult<Term<'a>> {

    match token {
        Token::Tuple(sub_tokens) => {
            let mut tuple_entries = Vec::with_capacity(sub_tokens.len());
            for sub_token in sub_tokens { tuple_entries.push(render_token(env, sub_token)?) }
            Ok(make_tuple(env, tuple_entries.as_slice()).encode(env))
        },
        Token::Array(sub_tokens) | Token::FixedArray(sub_tokens) => {
            let mut array_entries = Vec::with_capacity(sub_tokens.len());
            for sub_token in sub_tokens { array_entries.push( render_token(env, sub_token)?) }
            Ok(array_entries.encode(env))
        },
        Token::Bool(b) => Ok(b.encode(env)),
        Token::Address(a) => Ok(format!("0x{:x}", a).encode(env)),
        Token::Uint(u) | Token::Int(u) => Ok(format!("{}", u).encode(env)),
        _ => Ok(format!("{}", token).encode(env))
    }
}

