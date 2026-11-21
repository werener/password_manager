use serde::{Deserialize, Deserializer};

/// Deserializes `Option<T>` as `Some(Option<T>)` so JSON `null` can clear a field.
pub fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}
