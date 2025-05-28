macro_rules! ok_or_rcode {
    ($result:expr, mut $response:expr, $rcode:expr) => {
        match $result {
            Ok(val) => val,
            Err(_) => {
                $response.set_response_code($rcode);

                return Ok($response);
            }
        }
    };
}

macro_rules! error {
    ($($message:tt)*) => ({
        eprintln!($($message)*);
        std::process::exit(1);
    })
}
