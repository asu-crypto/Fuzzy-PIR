#!/usr/bin/env python3

from sage.all import *

def interpolate_polynomial_over_prime_field(points, prime):
    """
    Interpolate a polynomial over a prime field given points.
    
    Args:
        points: List of (x, y) tuples representing points
        prime: Prime number defining the field
    
    Returns:
        Polynomial over the prime field
    """
    # Create the finite field
    F = GF(prime)
    
    # Create polynomial ring over the field
    R = PolynomialRing(F, 'x')
    x = R.gen()
    
    # Extract x and y coordinates
    x_coords = [F(point[0]) for point in points]
    y_coords = [F(point[1]) for point in points]
    
    # Perform Lagrange interpolation
    poly = R.lagrange_polynomial(list(zip(x_coords, y_coords)))
    
    return poly

def verify_interpolation(poly, points, prime):
    """Verify that the polynomial evaluates correctly at given points."""
    F = GF(prime)
    R = PolynomialRing(F, 'x')
    x = R.gen()
    
    print("Verification:")
    for point in points:
        x_val, y_val = F(point[0]), F(point[1])
        computed_y = poly(x_val)
        print(f"  f({x_val}) = {computed_y}, expected = {y_val}, match = {computed_y == y_val}")

def main():
    min_group_size = 256
    bv_len = 10
    hd_threshold = 4 # The threshold for Hamming distance, points with x <= threshold will have y=1, others y=0

    prime = next_prime(max(min_group_size, bv_len) + 1) # Ensure prime is larger than both group size and bit vector length

    assert hd_threshold <= bv_len, "Threshold must be less than or equal to bit vector length."
    
    points = [(x,1 if x <= hd_threshold else 0) for x in range(0, bv_len)]
    
    print(f"Interpolating polynomial over GF({prime})")
    print(f"Points: {points}")
    
    # Interpolate the polynomial
    poly = interpolate_polynomial_over_prime_field(points, prime)
    
    print(f"\nPolynomial Coefficients: {poly.list()}")
    print(f"Polynomial: {poly}")
    # print(f"Degree: {poly.degree()}")
    
    # Verify the interpolation
    #verify_interpolation(poly, points, prime)
    
    # Evaluate at additional points
    #F = GF(prime)
    #print(f"\nAdditional evaluations:")
    #for x_val in [4, 6, 10]:
    #    y_val = poly(F(x_val))
    #    print(f"  f({x_val}) = {y_val}")



if __name__ == "__main__":
    main()
