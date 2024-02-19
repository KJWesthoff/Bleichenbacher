from TypeChecking.Annotations import typecheck
from Oracle.Oracle import Oracle
from PKCS.Formatting import os2ip, i2osp
from sys import stdout



@typecheck
def interval(a: int, b: int) -> range:
    return range(a, b + 1)


@typecheck
def ceildiv(a: int, b: int) -> int:
    """
    http://stackoverflow.com/a/17511341
    """
    return -(-a // b)


@typecheck
def floordiv(a: int, b: int) -> int:
    """
    http://stackoverflow.com/a/17511341
    """
    return a // b


@typecheck
def bleichenbacher(oracle: Oracle):
    """
    Bleichenbacher's attack

    Good ideas taken from:
        http://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html
    """


    ## keysize, modulo, encryption exponent
    k, n, e = oracle.get_k(), oracle.get_n(), oracle.get_e()


    ## Initial conditions for B () 
    B = pow(2, 8 * (k - 2))
    B2 = 2 * B
    B3 = B2 + B

    #@typecheck
    def pkcs_conformant(c_param: int, s_param: int) -> bool:
        """
        Helper-Function to check for PKCS conformance.
        """
        pkcs_conformant.counter += 1
        return oracle.decrypt(i2osp(c_param * pow(s_param, e, n) % n, k))


    pkcs_conformant.counter = 0

    
    ## Initial c_0 and s_0 (intercepted cipher text and '1')
    cipher = os2ip(oracle.eavesdrop())
    assert(pkcs_conformant(cipher, 1)) 
    
    
    c_0 = cipher
    set_m_old = {(B2, B3 - 1)}
    i = 1

    s_old = 0
    while True:
        if i == 1:
            s_new = ceildiv(n, B3)
            while not pkcs_conformant(c_0, s_new):
                s_new += 1

        elif i > 1 and len(set_m_old) >= 2:
            s_new = s_old + 1
            while not pkcs_conformant(c_0, s_new):
                s_new += 1 ## add 1 to s

        elif len(set_m_old) == 1:
            a, b = next(iter(set_m_old))
            found = False
            r = ceildiv(2 * (b * s_old - B2), n)
            while not found:
                for s in interval(ceildiv(B2 + r*n, b), floordiv(B3 - 1 + r*n, a)):
                    if pkcs_conformant(c_0, s):
                        found = True
                        s_new = s
                        break
                r += 1

        set_m_new = set()
        for a, b in set_m_old:
            r_min = ceildiv(a * s_new - B3 + 1, n)
            r_max = floordiv(b * s_new - B2, n)
            for r in interval(r_min, r_max):
                new_lb = max(a, ceildiv(B2 + r*n, s_new))
                new_ub = min(b, floordiv(B3 - 1 + r*n, s_new))
                if new_lb <= new_ub:  # intersection must be non-empty
                    set_m_new |= {(new_lb, new_ub)}

        print("Calculated new intervals set_m_new = {} in Step 3".format(set_m_new))

        if len(set_m_new) == 1: ## If both ends of interval is the same
            a, b = next(iter(set_m_new))
            if a == b:
                print("Calculated:     ", i2osp(a, k))
                print("Calculated int: ", a)
                print("Success after {} calls to the oracle.".format(pkcs_conformant.counter))
                return a

        i += 1
        s_old = s_new
        set_m_old = set_m_new


if __name__ == "__main__":
    secret = "Do not share this..AES key!!"
    oracle = Oracle(secret)
    res = bleichenbacher(oracle), oracle.get_k()
    res_bytes = i2osp(res[0], res[1])
    
    print("res bytes is:, ", res_bytes)

    # Decode the bytes to a UTF-8 string
    utf8_string = res_bytes.decode('utf-8', errors='ignore')
    print(utf8_string)