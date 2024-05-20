macro_rules! ok_or_rcode {
    ($result:expr, mut $query:expr, $rcode:expr) => {
        match $result {
            Ok(val) => val,
            Err(_) => {
                $query.flags.rcode = $rcode;

                return Ok(());
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
