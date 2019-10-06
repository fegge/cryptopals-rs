use std::collections::HashMap;


#[derive(Debug)]
pub enum Error {
    EncodingError,
    DecodingError
}


pub trait ToParamStr {
    fn to_param_str(&self) -> String;
}


pub trait FromParamStr where Self: Sized {
    fn from_param_str(string: &str) -> Result<Self, Error>;
}


// We need K and V to be ToString since we update
// the individual key/values before writing them
// to the parameter string.
impl<K, V> ToParamStr for HashMap<K, V> where 
    K: ToString,
    V: ToString {
    fn to_param_str(&self) -> String {
        self.iter()
            .map(|(key, value): (&K, &V)| {
                let key: String = key.to_string();
                let value: String = value.to_string();
                format!(
                    "{}={}", 
                    key.replace("&", "%26").replace("=", "%3D"),
                    value.replace("&", "%26").replace("=", "%3D")
                )
            })
            .collect::<Vec<String>>()
            .join("&")
    }
}


impl FromParamStr for HashMap<String, String> {
    fn from_param_str(param_str: &str) -> Result<Self, Error> {
        let mut result: HashMap<String, String> = HashMap::new();
        let params = param_str.split("&");
        for param in params {
            let mut tokens = param.split("=");
            match (tokens.next(), tokens.next()) {
                (Some(key), Some(value)) => {
                    result.insert(key.to_owned(), value.to_owned());
                },
                _ => return Err(Error::DecodingError)
            };
        }
        Ok(result)
    }
}
