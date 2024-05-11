/// Running stat implementation based on Knuth TAOCP vol 2, 3rd edition, page
/// 232. Where we have the recurrences for 2 <= k <= n:
///
/// - M_{1} = x_{1}, M_{k} = M_{k-1} + ( x_{k} - M_{k-1} ) / k
/// - S_{1} = 0,     S_{k} = S_{k-1} + ( x_{k} - M_{k-1} ) * ( x_{k} - M_{k} )
///
/// Where M_{k} is the mean and the variance is equal to S_{k} / (k - 1) at the
/// step k
#[derive(Debug)]
pub struct RunningStat {
    count: u64,
    sum: u64,
    min: u64,
    max: u64,
    mean: f64,
    /// Variance without dividing by total_count-1
    sq_diff: f64,
}

impl RunningStat {
    pub fn new() -> RunningStat {
        RunningStat {
            count: 0,
            sum: 0,
            min: u64::MAX,
            max: u64::MIN,
            mean: 0.0,
            sq_diff: 0.0,
        }
    }

    pub fn include(&mut self, value: u64) {
        // Accoumate integer values
        self.count += 1;
        self.sum += value;
        self.min = std::cmp::min(self.min, value);
        self.max = std::cmp::max(self.max, value);

        // List reccurence values
        let value = value as f64;
        let total = self.count as f64;
        let previous_mean = self.mean;
        let previous_sq_diff = self.sq_diff;

        // Apply recurrence
        let next_mean = previous_mean + (value - previous_mean) / total;
        let next_sq_diff = previous_sq_diff + (value - previous_mean) * (value - next_mean);

        // Store values
        self.mean = next_mean;
        self.sq_diff = next_sq_diff;
    }

    #[allow(dead_code)]
    pub fn current_count(&self) -> u64 {
        self.count
    }

    pub fn current_sum(&self) -> u64 {
        self.sum
    }

    pub fn current_min(&self) -> Option<u64> {
        if self.count == 0 {
            None
        } else {
            Some(self.min)
        }
    }

    pub fn current_max(&self) -> Option<u64> {
        if self.count == 0 {
            None
        } else {
            Some(self.max)
        }
    }

    pub fn current_mean(&self) -> f64 {
        self.mean
    }

    pub fn current_variance(&self) -> f64 {
        if self.count == 1 {
            0.0
        } else {
            self.sq_diff / (self.count as f64 - 1.0)
        }
    }

    pub fn current_standard_deviation(&self) -> f64 {
        f64::sqrt(self.current_variance())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correct_computation() {
        let mut v = RunningStat::new();

        v.include(10);

        assert_eq!(v.current_count(), 1);
        assert_eq!(v.current_sum(), 10);
        assert_eq!(v.current_mean(), 10.0);
        assert_eq!(v.sq_diff, 0.0);
        assert_eq!(v.current_variance(), 0.0);
        assert_eq!(v.current_standard_deviation(), 0.0);

        v.include(20);

        assert_eq!(v.current_count(), 2);
        assert_eq!(v.current_sum(), 30);
        assert_eq!(v.current_mean(), 15.0);
        assert_eq!(v.sq_diff, 50.0);
        assert_eq!(v.current_variance(), 50.0);
        assert_eq!(v.current_standard_deviation(), f64::sqrt(50.0));

        v.include(15);

        assert_eq!(v.current_count(), 3);
        assert_eq!(v.current_sum(), 45);
        assert_eq!(v.current_mean(), 15.0);
        assert_eq!(v.sq_diff, 50.0);
        assert_eq!(v.current_variance(), 25.0);
        assert_eq!(v.current_standard_deviation(), f64::sqrt(25.0));

        v.include(15);

        assert_eq!(v.current_count(), 4);
        assert_eq!(v.current_sum(), 60);
        assert_eq!(v.current_mean(), 15.0);
        assert_eq!(v.sq_diff, 50.0);
        assert_eq!(v.current_variance(), 50.0 / 3.0);
        assert_eq!(v.current_standard_deviation(), f64::sqrt(50.0 / 3.0));

        v.include(20);

        assert_eq!(v.current_count(), 5);
        assert_eq!(v.current_sum(), 80);
        assert_eq!(v.current_mean(), 16.0);
        assert_eq!(v.sq_diff, 70.0);
        assert_eq!(v.current_variance(), 70.0 / 4.0);
        assert_eq!(v.current_standard_deviation(), f64::sqrt(70.0 / 4.0));
    }
}
