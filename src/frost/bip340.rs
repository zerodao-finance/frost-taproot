use elliptic_curve::{
    ops::Reduce,
    sec1::{Coordinates, ToEncodedPoint},
    subtle::Choice,
    DecompressPoint, PrimeField,
};

pub fn get_xy_coords(e: k256::AffinePoint) -> (k256::Scalar, k256::Scalar) {
    match e.to_encoded_point(false).coordinates() {
        Coordinates::Uncompressed { x, y } => {
            // if this can fail it only does it with negligible probability
            (
                k256::Scalar::from_repr(*x).unwrap(),
                k256::Scalar::from_repr(*y).unwrap(),
            )
        }
        _ => panic!(".coordinates() did not return expected variant"),
    }
}

// from BIP340
//
// the coinbase code for secp256k1 also counts this as being "positive"
pub fn has_even_y(e: k256::AffinePoint) -> bool {
    let comp = e.to_encoded_point(true);
    match comp.coordinates() {
        Coordinates::Compressed { y_is_odd, .. } => !y_is_odd,
        _ => panic!(".coordinates() did not return expected variant"),
    }
}

// from BIP340
pub fn normalize_point(e: k256::AffinePoint) -> k256::AffinePoint {
    if !has_even_y(e) {
        flip(e)
    } else {
        e
    }
}

// from BIP340, flips the y coordinate by the field order or something
pub fn flip(e: k256::AffinePoint) -> k256::AffinePoint {
    -e
}

// from BIP340
pub fn lift_x(e: k256::U256) -> k256::AffinePoint {
    let s = k256::Scalar::from_uint_reduced(e); // actually this mods it but okay
    let sbuf = s.to_bytes();
    k256::AffinePoint::decompress(&sbuf, Choice::from(0)).unwrap()
}

pub fn fmt_point(e: &k256::AffinePoint) -> String {
    let ep = e.to_encoded_point(true);
    match ep.coordinates() {
        Coordinates::Compressed { x, y_is_odd } => {
            let eo = if y_is_odd { "odd" } else { "evn" };
            format!("[{}:{}]", eo, hex::encode(x))
        }
        Coordinates::Identity => {
            format!("[identity]")
        }
        _ => panic!(".coordinates() did not return compressed instance"),
    }
}

/// Checks if the X-coordinates of points are equal, so we ignore the Y-coordinate.
pub fn eq_ignore_parity(a: k256::AffinePoint, b: k256::AffinePoint) -> bool {
    use elliptic_curve::AffineXCoordinate;
    let ax = a.x();
    let bx = b.x();
    ax == bx
}
