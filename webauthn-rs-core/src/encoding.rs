//! This file contains WebAuthn encoding / serialization helper functions
//! for usage with Aptos' [`AccountAuthenticator`](https://github.com/aptos-labs/aptos-core/blob/main/types/src/transaction/authenticator.rs#L383)
//! for WebAuthn transactions.

#![warn(missing_docs)]

use base64urlsafedata::Base64UrlSafeData;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json;
use webauthn_rs_proto::TokenBinding;

/// Determines if the `Base64UrlSafeData` is_empty
pub(crate) fn is_base64_url_safe_data_empty(data: &Base64UrlSafeData) -> bool {
    data.0.is_empty()
}

/// `SerializableCollectedClientData` is a modified version of
/// [`CollectedClientData`](crate::internals::CollectedClientData) that
/// conforms to the JSON byte serialization format expected of `CollectedClientData`,
/// detailed in section §5.8.1.1 Serialization of the WebAuthn spec.
///
/// Note: `SerializableCollectedClientData` should only be used in circumstances that require
/// byte serialization of the struct. It does NOT include the same checks for fields as
/// `CollectedClientData` and will be serialized differently.
///
/// Changes to `CollectedClientData` include:
/// 1.  serde `skip_serializing_if` applied to `type_`, `challenge`, `origin`, and `token_binding`.
///     This is for serialization steps 11-13 of [`serialize_serializeable_collected_client_data`](serialize_serializeable_collected_client_data)
/// 2. `origin` is String instead of `url::Url`. This implies that empty strings are allowed, which
///     is needed for step 11 of `serialize_serializeable_collected_client_data`.
/// 3. `unknown_keys` uses `IndexMap` instead of `BTreeMap` to preserve ordering of keys so that
///    `to_bytes()` is consistent with the bytes in `AuthenticatorAssertionResponse`.
///     The ordering is significant because the WebAuthn signature is computed over these bytes
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct SerializableCollectedClientData {
    /// The credential type
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub type_: String,
    /// The challenge.
    #[serde(skip_serializing_if = "is_base64_url_safe_data_empty")]
    pub challenge: Base64UrlSafeData,
    /// The rp origin as the browser understood it.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub origin: String,
    /// The inverse of the sameOriginWithAncestors argument value that was
    /// passed into the internal method.
    #[serde(rename = "crossOrigin", skip_serializing_if = "Option::is_none")]
    pub cross_origin: Option<bool>,
    /// tokenBinding.
    #[serde(rename = "tokenBinding", skip_serializing_if = "Option::is_none")]
    pub token_binding: Option<TokenBinding>,
    /// This struct can be extended, so it's important to be tolerant of unknown
    /// keys.
    #[serde(flatten)]
    pub unknown_keys: IndexMap<String, serde_json::value::Value>,
}

impl SerializableCollectedClientData {
    /// Uses custom JSON byte serialization referenced in the WebAuthn specification, under
    /// §5.8.1.1 Serialization
    pub fn to_bytes(&self) -> Vec<u8> {
        serialize_serializeable_collected_client_data(self)
    }

    /// Helper function to determine if `SerializableCollectedClientData` is empty
    pub fn is_empty(&self) -> bool {
        self.type_.is_empty()
            && self.challenge.0.is_empty()
            && self.origin.is_empty()
            && self.cross_origin.is_none()
            && self.token_binding.is_none()
            && self.unknown_keys.is_empty()
    }
}

/// The function `ccd_to_string` is used in
/// [`serialize_serializeable_collected_client_data`](serialize_serializeable_collected_client_data)
/// and is defined as:
/// 1. Let encoded be an empty byte string.
/// 2. Append 0x22 (") to encoded. -> 0x22 is the hexadecimal for a double quote (")
/// 3. Invoke ToString on the given object to convert to a string.
/// 4. For each code point in the resulting string, if the code point:
///     
///     -> is in the set {U+0020, U+0021, U+0023–U+005B, U+005D–U+10FFFF}
///             Append the UTF-8 encoding of that code point to encoded.
///
///     -> is U+0022
///             Append 0x5c22 (\") to encoded.
///
///     -> is U+005C
///             Append 0x5c5c (\\) to encoded.
///
///     -> otherwise
///             Append 0x5c75 (\u) to encoded, followed by four, lower-case hex digits that,
///             when interpreted as a base-16 number, represent that code point.
///
/// 5. Append 0x22 (") to encoded.
/// 6. The result of this function is the value of encoded.
pub(crate) fn ccd_to_string(input: &str) -> Vec<u8> {
    let mut encoded = Vec::new();

    // Append 0x22 (")
    encoded.push(0x22);

    for code_point in input.chars() {
        match code_point {
            '\u{0020}' | '\u{0021}' | '\u{0023}'..='\u{005B}' | '\u{005D}'..='\u{10FFFF}' => {
                // Append the UTF-8 encoding of the code point
                let utf8_bytes = code_point.to_string().into_bytes();
                encoded.extend_from_slice(&utf8_bytes);
            }
            '\u{0022}' => {
                // Append 0x5c22 (\")
                encoded.push(0x5c);
                encoded.push(0x22);
            }
            '\u{005C}' => {
                // Append 0x5c5c (\\)
                encoded.push(0x5c);
                encoded.push(0x5c);
            }
            _ => {
                // Append 0x5c75 (\u) followed by four lower-case hex digits
                encoded.push(0x5c);
                encoded.push(0x75);
                let hex_digits = format!("{:04x}", code_point as u32);
                for hex_byte in hex_digits.bytes() {
                    encoded.push(hex_byte);
                }
            }
        }
    }

    // Append 0x22 (")
    encoded.push(0x22);

    encoded
}

/// This is the custom serialization of [`CollectedClientData`](crate::internals::CollectedClientData)
/// that is performed by the device authenticator, referenced in the WebAuthn spec, under
/// Section §5.8.1.1 Serialization.
///
/// This is helpful for testing the device authenticator output for clientDataJSON in client
/// assertions.
///
/// Unfortunately `serde_json::to_vec` does NOT properly serialize [`CollectedClientData`](crate::internals::CollectedClientData).
/// You MUST use the custom serializer below in order to serialize it back into `clientDataJSON`
/// as returned by the user agent during an `AuthenticatorAssertionResponse`
///
/// The serialization of the [`CollectedClientData`](crate::internals::CollectedClientData)
/// is a subset of the algorithm for JSON-serializing
/// to bytes. I.e. it produces a valid JSON encoding of the `CollectedClientData` but also provides
/// additional structure that may be exploited by verifiers to avoid integrating a full JSON parser.
/// While verifiers are recommended to perform standard JSON parsing, they may use the more
/// limited algorithm below in contexts where a full JSON parser is too large. This verification
/// algorithm requires only base64url encoding, appending of bytestrings (which could be
/// implemented by writing into a fixed template), and three conditional checks (assuming that
/// inputs are known not to need escaping).
///
/// The serialization algorithm works by appending successive byte strings to an, initially empty,
/// partial result until the complete result is obtained.
///
/// 1. Let result be an empty byte string.
/// 2. Append 0x7b2274797065223a ({"type":) to result.
/// 3. Append CCDToString(type) to result.
/// 4. Append 0x2c226368616c6c656e6765223a (,"challenge":) to result.
/// 5. Append CCDToString(challenge) to result.
/// 6. Append 0x2c226f726967696e223a (,"origin":) to result.
/// 7. Append CCDToString(origin) to result.
/// 8. Append 0x2c2263726f73734f726967696e223a (,"crossOrigin":) to result.
/// 9. If crossOrigin is not present, or is false:
///     1. Append 0x66616c7365 (false) to result.
/// 10. Otherwise:
///     1. Append 0x74727565 (true) to result.
/// 11. Create a temporary copy of the CollectedClientData and remove the fields
///     type, challenge, origin, and crossOrigin (if present).
/// 12. If no fields remain in the temporary copy then:
///     1. Append 0x7d (}) to result.
/// 13. Otherwise:
///     1. Invoke serialize JSON to bytes on the temporary copy to produce a byte string remainder.
///         (see below for how this is done)
///     2. Append 0x2c (,) to result.
///     3. Remove the leading byte from remainder.
///     4. Append remainder to result.
/// 14. The result of the serialization is the value of result.
///
/// From step 13.1
/// To serialize a JavaScript value to JSON bytes, given a JavaScript value value:
///     1. Let string be the result of serializing a JavaScript value to a JSON string given value.
///     2. Return the result of running UTF-8 encode on string. [ENCODING]
pub fn serialize_serializeable_collected_client_data(
    sccd: &SerializableCollectedClientData,
) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();

    // Append {"type":
    result.extend(b"{\"type\":");
    // Append type value
    result.extend(ccd_to_string(sccd.type_.as_str()));
    // Append ,"challenge":
    result.extend(b",\"challenge\":");
    // Append challenge value
    result.extend(ccd_to_string(sccd.challenge.to_string().as_str()));
    // Append ,"origin":
    result.extend(b",\"origin\":");
    // Append origin value
    result.extend(ccd_to_string(sccd.origin.as_str()));
    // Append ,"crossOrigin":
    result.extend(b",\"crossOrigin\":");

    if let Some(cross_origin) = sccd.cross_origin {
        if cross_origin {
            // Append true
            result.extend(b"true");
        } else {
            // Append false
            result.extend(b"false");
        }
    } else {
        // Append false if crossOrigin is not present
        result.extend(b"false");
    }

    // Create a temporary copy of CollectedClientData without type, challenge, origin, and crossOrigin
    let mut temp_copy = sccd.clone();
    temp_copy.type_ = "".to_string();
    temp_copy.challenge = Base64UrlSafeData::try_from("")
        .expect("Unable to generate Base64UrlSafeData from empty string");
    temp_copy.origin = "".to_string();
    temp_copy.cross_origin = None;

    // Check if any fields remain in the temporary copy
    if temp_copy.is_empty() {
        // If no fields remain, append }
        result.push(b'}');
    } else {
        // Otherwise, invoke serialize JSON to bytes on the temporary copy to produce a byte string remainder
        let remainder = serde_json::to_vec(&temp_copy)
            .expect("Unable to serialize SerializeableCollectedClientData to vector");

        // Append ,
        result.push(b',');

        // Remove the leading byte from remainder
        let mut remainder = remainder.into_iter();
        remainder.next();

        // Append remainder to result
        result.extend(remainder);
    }

    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use crate::encoding::SerializableCollectedClientData;

    /// This is a Secure Payment Confirmation (SPC) response. SPC assertion responses
    /// extend the `CollectedClientData` struct by adding a "payment" field that
    /// normally does not exist on `CollectedClientData`
    static EXTENDED_CLIENT_DATA_BYTES: [u8; 414] = [
        123, 34, 116, 121, 112, 101, 34, 58, 34, 112, 97, 121, 109, 101, 110, 116, 46, 103, 101,
        116, 34, 44, 34, 99, 104, 97, 108, 108, 101, 110, 103, 101, 34, 58, 34, 90, 69, 118, 77,
        102, 108, 90, 68, 99, 119, 81, 74, 109, 97, 114, 73, 110, 110, 89, 105, 56, 56, 112, 120,
        45, 54, 72, 90, 99, 118, 50, 85, 111, 120, 119, 55, 45, 95, 74, 79, 79, 84, 103, 34, 44,
        34, 111, 114, 105, 103, 105, 110, 34, 58, 34, 104, 116, 116, 112, 58, 47, 47, 108, 111, 99,
        97, 108, 104, 111, 115, 116, 58, 52, 48, 48, 48, 34, 44, 34, 99, 114, 111, 115, 115, 79,
        114, 105, 103, 105, 110, 34, 58, 102, 97, 108, 115, 101, 44, 34, 112, 97, 121, 109, 101,
        110, 116, 34, 58, 123, 34, 114, 112, 73, 100, 34, 58, 34, 108, 111, 99, 97, 108, 104, 111,
        115, 116, 34, 44, 34, 116, 111, 112, 79, 114, 105, 103, 105, 110, 34, 58, 34, 104, 116,
        116, 112, 58, 47, 47, 108, 111, 99, 97, 108, 104, 111, 115, 116, 58, 52, 48, 48, 48, 34,
        44, 34, 112, 97, 121, 101, 101, 79, 114, 105, 103, 105, 110, 34, 58, 34, 104, 116, 116,
        112, 115, 58, 47, 47, 108, 111, 99, 97, 108, 104, 111, 115, 116, 58, 52, 48, 48, 48, 34,
        44, 34, 116, 111, 116, 97, 108, 34, 58, 123, 34, 118, 97, 108, 117, 101, 34, 58, 34, 49,
        46, 48, 49, 34, 44, 34, 99, 117, 114, 114, 101, 110, 99, 121, 34, 58, 34, 65, 80, 84, 34,
        125, 44, 34, 105, 110, 115, 116, 114, 117, 109, 101, 110, 116, 34, 58, 123, 34, 105, 99,
        111, 110, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 97, 112, 116, 111, 115, 108, 97,
        98, 115, 46, 99, 111, 109, 47, 97, 115, 115, 101, 116, 115, 47, 102, 97, 118, 105, 99, 111,
        110, 45, 50, 99, 57, 101, 50, 51, 97, 98, 99, 51, 97, 51, 102, 52, 99, 52, 53, 48, 51, 56,
        101, 56, 99, 55, 56, 52, 98, 48, 97, 52, 101, 99, 98, 57, 48, 53, 49, 98, 97, 97, 46, 105,
        99, 111, 34, 44, 34, 100, 105, 115, 112, 108, 97, 121, 78, 97, 109, 101, 34, 58, 34, 80,
        101, 116, 114, 97, 32, 116, 101, 115, 116, 34, 125, 125, 125,
    ];

    // Normal client data from Chrome assertion
    static CLIENT_DATA_BYTES: [u8; 134] = [
        123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117, 116, 104, 110, 46, 103,
        101, 116, 34, 44, 34, 99, 104, 97, 108, 108, 101, 110, 103, 101, 34, 58, 34, 90, 69, 118,
        77, 102, 108, 90, 68, 99, 119, 81, 74, 109, 97, 114, 73, 110, 110, 89, 105, 56, 56, 112,
        120, 45, 54, 72, 90, 99, 118, 50, 85, 111, 120, 119, 55, 45, 95, 74, 79, 79, 84, 103, 34,
        44, 34, 111, 114, 105, 103, 105, 110, 34, 58, 34, 104, 116, 116, 112, 58, 47, 47, 108, 111,
        99, 97, 108, 104, 111, 115, 116, 58, 52, 48, 48, 48, 34, 44, 34, 99, 114, 111, 115, 115,
        79, 114, 105, 103, 105, 110, 34, 58, 102, 97, 108, 115, 101, 125,
    ];

    /// Validate that the custom `serialize_collected_client_data` function
    /// above serializes `CollectedClientData` correctly, even when the struct has been extended
    ///

    #[test]
    fn validate_extended_client_data_encoding() {
        let expected_client_data: SerializableCollectedClientData =
            serde_json::from_slice(EXTENDED_CLIENT_DATA_BYTES.as_slice()).unwrap();
        let expected_client_data_string = serde_json::to_string(&expected_client_data).unwrap();

        // This is a sample Secure Payment Confirmation (SPC) client_data response
        // It will help us test for any issues in extensibility of the CollectedClientData struct
        // More info: https://www.w3.org/TR/secure-payment-confirmation/#sctn-collectedclientpaymentdata-dictionary
        let actual_client_data_json = r#"{
            "type": "payment.get",
            "challenge": "ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg",
            "origin": "http://localhost:4000",
            "crossOrigin": false,
            "payment": {
                "rpId": "localhost",
                "topOrigin": "http://localhost:4000",
                "payeeOrigin": "https://localhost:4000",
                "total": {
                    "value": "1.01",
                    "currency": "APT"
                },
                "instrument": {
                    "icon": "https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico",
                    "displayName": "Petra test"
                }
            }
        }"#;

        let actual_client_data: SerializableCollectedClientData =
            serde_json::from_str(actual_client_data_json).unwrap();
        let actual_client_data_string = serde_json::to_string(&actual_client_data).unwrap();

        // String serializations should work perfectly fine with serde_json
        assert_eq!(expected_client_data_string, actual_client_data_string);

        let actual_client_data_bytes = actual_client_data.to_bytes();

        // Should be equal
        assert_eq!(
            EXTENDED_CLIENT_DATA_BYTES.to_vec(),
            actual_client_data_bytes
        )
    }
    #[test]
    fn validate_extended_client_data_encoding_failure() {
        // This is a sample Secure Payment Confirmation (SPC) client_data response
        // The ordering is switched and this should fail
        let actual_client_data_json = r#"{
            "type": "payment.get",
            "challenge": "ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg",
            "origin": "http://localhost:4000",
            "crossOrigin": false,
            "payment": {
                "topOrigin": "http://localhost:4000",
                "rpId": "localhost",
                "payeeOrigin": "https://localhost:4000",
                "total": {
                    "value": "1.01",
                    "currency": "APT"
                },
                "instrument": {
                    "icon": "https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico",
                    "displayName": "Petra test"
                }
            }
        }"#;

        let actual_client_data: SerializableCollectedClientData =
            serde_json::from_str(actual_client_data_json).unwrap();
        let actual_client_data_bytes = actual_client_data.to_bytes();

        // Should not be equal
        assert_ne!(CLIENT_DATA_BYTES.to_vec(), actual_client_data_bytes);
    }

    #[test]
    fn validate_normal_client_data_encoding() {
        let expected_client_data: SerializableCollectedClientData =
            serde_json::from_slice(CLIENT_DATA_BYTES.as_slice()).unwrap();
        let expected_client_data_string = serde_json::to_string(&expected_client_data).unwrap();

        // This is a sample Secure Payment Confirmation (SPC) client_data response
        // It will help us test for any issues in extensibility of the CollectedClientData struct
        // More info: https://www.w3.org/TR/secure-payment-confirmation/#sctn-collectedclientpaymentdata-dictionary
        let actual_client_data_json = r#"{
            "type": "webauthn.get",
            "challenge": "ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg",
            "origin": "http://localhost:4000",
            "crossOrigin": false
        }"#;

        let actual_client_data: SerializableCollectedClientData =
            serde_json::from_str(actual_client_data_json).unwrap();
        let actual_client_data_string = serde_json::to_string(&actual_client_data).unwrap();

        // String serializations should work perfectly fine with serde_json
        assert_eq!(expected_client_data_string, actual_client_data_string);

        let actual_client_data_bytes = actual_client_data.to_bytes();

        // Should be equal
        assert_eq!(CLIENT_DATA_BYTES.to_vec(), actual_client_data_bytes)
    }
}
