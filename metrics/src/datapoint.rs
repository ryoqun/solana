use std::{fmt, time::SystemTime};

#[derive(Clone, Debug)]
pub struct DataPoint {
    pub name: &'static str,
    pub timestamp: SystemTime,
    pub fields: Vec<(&'static str, String)>,
}

impl DataPoint {
    pub fn new(name: &'static str) -> Self {
        DataPoint {
            name,
            timestamp: SystemTime::now(),
            fields: vec![],
        }
    }

    pub fn add_field_str(&mut self, name: &'static str, value: &str) -> &mut Self {
        self.fields
            .push((name, format!("\"{}\"", value.replace('\"', "\\\""))));
        self
    }

    pub fn add_field_bool(&mut self, name: &'static str, value: bool) -> &mut Self {
        self.fields.push((name, value.to_string()));
        self
    }

    pub fn add_field_i64(&mut self, name: &'static str, value: i64) -> &mut Self {
        self.fields.push((name, value.to_string() + "i"));
        self
    }

    pub fn add_field_f64(&mut self, name: &'static str, value: f64) -> &mut Self {
        self.fields.push((name, value.to_string()));
        self
    }
}

impl fmt::Display for DataPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "datapoint: {}", self.name)?;
        for field in &self.fields {
            write!(f, " {}={}", field.0, field.1)?;
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! create_datapoint {
    (@field $point:ident $name:expr, $string:expr, String) => {
        $point.add_field_str($name, &$string);
    };
    (@field $point:ident $name:expr, $value:expr, i64) => {
        $point.add_field_i64($name, $value as i64);
    };
    (@field $point:ident $name:expr, $value:expr, f64) => {
        $point.add_field_f64($name, $value as f64);
    };
    (@field $point:ident $name:expr, $value:expr, bool) => {
        $point.add_field_bool($name, $value as bool);
    };

    (@fields $point:ident) => {};
    (@fields $point:ident ($name:expr, $value:expr, $type:ident) , $($rest:tt)*) => {
        $crate::create_datapoint!(@field $point $name, $value, $type);
        $crate::create_datapoint!(@fields $point $($rest)*);
    };
    (@fields $point:ident ($name:expr, $value:expr, $type:ident)) => {
        $crate::create_datapoint!(@field $point $name, $value, $type);
    };

    (@point $name:expr, $($fields:tt)+) => {
        {
            let mut point = $crate::datapoint::DataPoint::new(&$name);
            $crate::create_datapoint!(@fields point $($fields)+);
            point
        }
    };
    (@point $name:expr) => {
        $crate::datapoint::DataPoint::new(&$name)
    };
}

#[macro_export]
macro_rules! datapoint {
    ($level:expr, $name:expr) => {
        if log::log_enabled!($level) {
            $crate::submit($crate::create_datapoint!(@point $name), $level);
        }
    };
    ($level:expr, $name:expr, $($fields:tt)+) => {
        if log::log_enabled!($level) {
            $crate::submit($crate::create_datapoint!(@point $name, $($fields)+), $level);
        }
    };
}
#[macro_export]
macro_rules! datapoint_error {
    ($name:expr) => {
        $crate::datapoint!(log::Level::Error, $name);
    };
    ($name:expr, $($fields:tt)+) => {
        $crate::datapoint!(log::Level::Error, $name, $($fields)+);
    };
}

#[macro_export]
macro_rules! datapoint_warn {
    ($name:expr) => {
        $crate::datapoint!(log::Level::Warn, $name);
    };
    ($name:expr, $($fields:tt)+) => {
        $crate::datapoint!(log::Level::Warn, $name, $($fields)+);
    };
}

#[macro_export]
macro_rules! datapoint_info {
    ($name:expr) => {
        $crate::datapoint!(log::Level::Info, $name);
    };
    ($name:expr, $($fields:tt)+) => {
        $crate::datapoint!(log::Level::Info, $name, $($fields)+);
    };
}

#[macro_export]
macro_rules! datapoint_debug {
    ($name:expr) => {
        $crate::datapoint!(log::Level::Debug, $name);
    };
    ($name:expr, $($fields:tt)+) => {
        $crate::datapoint!(log::Level::Debug, $name, $($fields)+);
    };
}

#[macro_export]
macro_rules! datapoint_trace {
    ($name:expr) => {
        $crate::datapoint!(log::Level::Trace, $name);
    };
    ($name:expr, $($fields:tt)+) => {
        $crate::datapoint!(log::Level::Trace, $name, $($fields)+);
    };
}
