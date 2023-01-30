use std::ops::{Index, IndexMut};

/// A container for two identical-type objects which can be indexed using `bool`
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
pub struct Pair<T>([T; 2]);

impl<T> Pair<T> {
    #[inline]
    pub fn new(first: T, second: T) -> Self {
        Self([first, second])
    }

    pub fn iter(&self) -> std::slice::Iter<T> {
        self.0.iter()
    }
}

impl<T: Sized> Index<usize> for Pair<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        assert!(index == 0 || index == 1);
        &self.0[index]
    }
}

impl<T: Sized> IndexMut<usize> for Pair<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        assert!(index == 0 || index == 1);
        &mut self.0[index]
    }
}

impl<T: Sized> Index<bool> for Pair<T> {
    type Output = T;

    fn index(&self, index: bool) -> &Self::Output {
        &self.0[index as usize]
    }
}

impl<T: Sized> IndexMut<bool> for Pair<T> {
    fn index_mut(&mut self, index: bool) -> &mut Self::Output {
        &mut self.0[index as usize]
    }
}

// TODO
//
//impl<T: Serialize> Serialize for Pair<T> {
//    default fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
//        self.0.serialize(&mut writer)
//    }
//
//    default fn serialized_size(&self) -> usize {
//        self.0.serialized_size()
//    }
//}
//
//impl<T: Deserialize + Copy + Default> Deserialize for Pair<T> {
//    #[inline]
//    default fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
//        Ok(Pair(<[T; 2]>::deserialize(&mut reader)?))
//    }
//}
//
///// For `Pair<bool>` we can save space by encoding both bits into a single `u8`.
//impl Serialize for Pair<bool> {
//    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), SerializationError> {
//        let byte: u8 = (self[0] as u8) << 1 | self[1] as u8;
//        byte.serialize(&mut writer)
//    }
//
//    default fn serialized_size(&self) -> usize {
//        1
//    }
//}
//
///// For `Pair<bool>` we can save space by encoding both bits into a single `u8`.
//impl Deserialize for Pair<bool> {
//    #[inline]
//    fn deserialize<R: Read>(mut reader: R) -> Result<Self, SerializationError> {
//        let byte = <u8>::deserialize(&mut reader)?;
//        Ok(Pair([(byte & 2) == 2, (byte & 1) == 1]))
//    }
//}
