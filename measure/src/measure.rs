use {
    solana_sdk::timing::duration_as_ns,
    std::{fmt, time::Instant},
};

#[derive(Debug)]
pub struct Measure {
    name: &'static str,
    start: Instant,
    duration: u64,
}

impl Measure {
    pub fn start(name: &'static str) -> Self {
        Self {
            name,
            start: Instant::now(),
            duration: 0,
        }
    }

    pub fn stop(&mut self) {
        self.duration = duration_as_ns(&self.start.elapsed());
    }

    pub fn as_ns(&self) -> u64 {
        self.duration
    }

    pub fn as_us(&self) -> u64 {
        self.duration / 1000
    }

    pub fn as_ms(&self) -> u64 {
        self.duration / (1000 * 1000)
    }

    pub fn as_s(&self) -> f32 {
        self.duration as f32 / (1000.0f32 * 1000.0f32 * 1000.0f32)
    }

    /// Measure this function
    ///
    /// Use `Measure::this()` when you have a function that you want to measure.  `this()` will
    /// start a new `Measure`, call your function, stop the measure, then return the `Measure`
    /// object along with your function's return value.
    ///
    /// If your function takes more than one parameter, you will need to wrap your function in a
    /// closure, and wrap the arguments in a tuple.  The same thing applies to methods.  See the
    /// tests for more details.
    ///
    /// # Examples
    ///
    /// ```
    /// // Call a function with a single argument
    /// # use solana_measure::measure::Measure;
    /// # fn my_function(fizz: i32) -> i32 { fizz }
    /// let (result, measure) = Measure::this(my_function, 42, "my_func");
    /// # assert_eq!(result, 42);
    /// ```
    ///
    /// ```
    /// // Call a function with multiple arguments
    /// # use solana_measure::measure::Measure;
    /// let (result, measure) = Measure::this(|(arg1, arg2)| std::cmp::min(arg1, arg2), (42, 123), "minimum");
    /// # assert_eq!(result, 42);
    /// ```
    ///
    /// ```
    /// // Call a method
    /// # use solana_measure::measure::Measure;
    /// # struct Foo { x: i32 }
    /// # impl Foo { fn bar(&self, arg: i32) -> i32 { self.x + arg } }
    /// # let baz = 8;
    /// let foo = Foo { x: 42 };
    /// let (result, measure) = Measure::this(|(this, args)| Foo::bar(&this, args), (&foo, baz), "Foo::bar");
    /// # assert_eq!(result, 50);
    /// ```
    pub fn this<T, R, F: FnOnce(T) -> R>(func: F, args: T, name: &'static str) -> (R, Self) {
        let mut measure = Self::start(name);
        let result = func(args);
        measure.stop();
        (result, measure)
    }
}

impl fmt::Display for Measure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.duration == 0 {
            write!(f, "{} running", self.name)
        } else if self.as_us() < 1 {
            write!(f, "{} took {}ns", self.name, self.duration)
        } else if self.as_ms() < 1 {
            write!(f, "{} took {}us", self.name, self.as_us())
        } else if self.as_s() < 1. {
            write!(f, "{} took {}ms", self.name, self.as_ms())
        } else {
            write!(f, "{} took {:.1}s", self.name, self.as_s())
        }
    }
}
