////////////////////////////////////////////////////////////////////////////////
//                                                               
// Efficient algorithms for supersingular isogeny Diffie-Hellman 
// Craig Costello, Patrick Longa, Michael Naehrig, 2016         
// (c) 2016 Microsoft Corporation. All rights reserved.         
//                                                                               
////////////////////////////////////////////////////////////////////////////////
                                                                
In this folder are four Magma scripts that are related to the above paper. The
main script is SIDH.mag, which contains all of the functions required to
implement SIDH key exchange. It can be called by setting the current (Magma)
directory to this folder, and entering 

load "SIDH.mag";

It will call "Validate.mag" to illustrate public key validation. 

The second script can be called by entering

load "Kummer_Weierstrass_equivalence.mag";

Its purpose is to show that our computations give the same result as Magma's.
In particular, we work explicitly on the Kummer variety of supersingular
curves, almost entirely in projective space P^1, and using the Montgomery
x-coordinate. This script shows that this gives equivalent results to the
traditional way of computing isogenies: i.e., Velu's formulas on the affine
Weierstrass model, which are implemented in Magma's "IsogenyFromKernel"
function. 

WARNING: The script "Kummer_Weierstrass_equivalence.mag" will take several
minutes to execute fully, since Magma's "IsogenyFromKernel" function is slow 
in contrast to the projective Kummer computations. 

Finally, the script "optimalstrategies.mag" computes an optimal strategy for
traversing the isogeny tree based on the cost ratios of computing an
m-isogeny versus the multiplication-by-m map. It follows the discussion in the
paper and is based on the original method described by De Feo, Jao and Plut:
Towards quantum-resistant cryptosystems from supersingular elliptic curve
isogenies, J. Math. Crypt., 8(3):209-247, 2014.          

