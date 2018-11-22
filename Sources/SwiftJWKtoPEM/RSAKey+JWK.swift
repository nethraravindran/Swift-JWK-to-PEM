/*
 Copyright 2017 IBM Corp.
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

import Foundation
import OpenSSL

public class RSAKey {
    
    private var key: OpaquePointer? = nil
    
    enum keyType {
        case privateKey
        case publicKey
    }
    
    private var type: keyType
    
    /**
     - parameter n: Base64 URL encoded string representing the `modulus` of the RSA Key.
     - parameter e: Base64 URL encoded string representing the `public exponent` of the RSA Key.
     - parameter d: Base64 URL encoded string representing the `private exponent` of the RSA Key.
     - parameter p: Base64 URL encoded string representing the `secret prime factor` of the RSA Key.
     - parameter q: Base64 URL encoded string representing the `secret prime factor` of the RSA Key.
     - parameter dp: Base64 URL encoded string representing the `first factor CRT exponent` of the RSA Key. `d mod (p-1)`
     - parameter dq: Base64 URL encoded string representing the `second factor CRT exponent` of the RSA Key. `d mod (q-1)`
     - parameter qi: Base64 URL encoded string representing the `first CRT coefficient` of the RSA Key. `q^-1 mod p`
     */
    public init(n: String, e: String, d: String? = nil,
                p: String? = nil, q: String? = nil,
                dp: String? = nil, dq: String? = nil,
                qi: String? = nil) throws {

        type = .publicKey

        let n_ptr = try base64URLToUInt(n)
        let n_bn = stringToBigNum(n_ptr.baseAddress, Int32(n_ptr.count))

        let e_ptr = try base64URLToUInt(e)
        let e_bn = stringToBigNum(e_ptr.baseAddress, Int32(e_ptr.count))

        var d_bn: OpaquePointer? = nil
        var p_bn: OpaquePointer? = nil
        var q_bn: OpaquePointer? = nil
        var dp_bn: OpaquePointer? = nil
        var dq_bn: OpaquePointer? = nil
        var qi_bn: OpaquePointer? = nil

        if let d = d {
           let d_ptr = try base64URLToUInt(d)
           d_bn = stringToBigNum(d_ptr.baseAddress, Int32(d_ptr.count))
           type = .privateKey
        }

        

        // p, q, dmp1, dmq1 and iqmp may be NULL in private keys,
        // but the RSA operations are much faster when these values are available.
        if let p = p {
           let p_ptr = try base64URLToUInt(p)
           p_bn = stringToBigNum(p_ptr.baseAddress, Int32(p_ptr.count))
        }

        if let q = q {
           let q_ptr = try base64URLToUInt(q)
           q_bn = stringToBigNum(q_ptr.baseAddress, Int32(q_ptr.count))
        }

        if let dp = dp {
           let dp_ptr = try base64URLToUInt(dp)
           dp_bn = stringToBigNum(dp_ptr.baseAddress, Int32(dp_ptr.count))
        }

        if let dq = dq {
           let dq_ptr = try base64URLToUInt(dq)
           dq_bn = stringToBigNum(dq_ptr.baseAddress, Int32(dq_ptr.count))
        }

        if let qi = qi {
           let qi_ptr = try base64URLToUInt(qi)
           qi_bn = stringToBigNum(qi_ptr.baseAddress, Int32(qi_ptr.count))
        }

        let rsakey = RSA_new()
        RSA_set0_key(rsakey, n_bn, e_bn, d_bn)
        RSA_set0_factors(rsakey, p_bn, q_bn)
        RSA_set0_crt_params(rsakey, dp_bn, dq_bn, qi_bn)

        // assign RSAkey to EVP_Pkey to keep
        // EVP_PKEY_assign_RSA but complex macro
        // EVP_PKEY_assign((pkey),EVP_PKEY_RSA,(char *)(rsa))
        key = EVP_PKEY_new()
        EVP_PKEY_assign(key, EVP_PKEY_RSA, .make(optional: rsakey))
        guard key != nil else {
            throw JWKError.createKey
        }
    }
    
    public convenience init(jwk: String) throws {
        
        if let jwkData = jwk.data(using: .utf8) {
            let jwkJSON = try? JSONDecoder().decode(JWK.self, from: jwkData)
            
            // Check presence of mandatory fields
            guard jwkJSON?.kty == "RSA", let modulus = jwkJSON?.n, let exp = jwkJSON?.e else {
                throw JWKError.input
            }
            
            try self.init(n: modulus, e: exp, d: jwkJSON?.d, p: jwkJSON?.p, q: jwkJSON?.q, dp: jwkJSON?.dp, dq: jwkJSON?.dq, qi: jwkJSON?.qi)
            
        } else {
            throw JWKError.input
        }
    }
    
    //        #if defined(OPENSSL_1_1_0)
    //            if (1 != RSA_set0_key(rsa, rsaModulusBn, rsaExponentBn, NULL); ERR_print_errors_fp(stdout);
    //                #else
    //                rsa->n = rsaModulusBn;
    //                rsa->e = rsaExponentBn;
    //        #endif
    
    deinit {
        if let key = key {
            EVP_PKEY_free(key)
        }
    }
    
    public func getPublicKey(_ encoding: certEncoding? = certEncoding.pemPkcs8) throws -> String? {
        
        // currently only support PEM PKCS#8
        guard encoding == certEncoding.pemPkcs8 else {
            throw JWKError.invalidKeyType
        }
        
        // PEM PKCS#8
        return try getPublicPEM()
    }
    
    public func getPrivateKey(_ encoding: certEncoding? = certEncoding.pemPkcs8) throws -> String? {
        
        // currently only support PEM PKCS#8
        guard encoding == certEncoding.pemPkcs8 else {
            throw JWKError.invalidKeyType
        }
        
        // PEM PKCS#8
        return try getPrivatePEM()
    }
    
    private func getPublicPEM() throws -> String? {
        
        // Public key can be extracted from both public and private keys
        guard ( type == keyType.publicKey || type == keyType.privateKey )  else {
            throw JWKError.invalidKeyType
        }
        
        let bio = BIO_new(BIO_s_mem())
        
        // writes EVP key to bio
        let  retval = PEM_write_bio_PUBKEY(bio, key)
        
        // get length of BIO that was created
        // BIO_PENDING is complex macro
        let publicKeyLen = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
        
        guard retval == 1, publicKeyLen > 0 else {
            throw JWKError.createPublicKey
        }
        
        // read the key from the buffer
        let publicKey: UnsafeMutablePointer<UInt8>? = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(publicKeyLen))
        BIO_read(bio, publicKey, Int32(publicKeyLen));
        
        let pk = Data(bytes: publicKey!, count: Int(publicKeyLen))
        return String(data: pk, encoding: .utf8)
    }
    
    private func getPrivatePEM() throws -> String? {
        
        guard type == keyType.privateKey else {
            throw JWKError.invalidKeyType
        }
        
        let bio = BIO_new(BIO_s_mem())
        
        // writes EVP key to bio
        let  retval = PEM_write_bio_PrivateKey(bio, key, nil, nil, 0, nil, nil);
        
        // get length of BIO that was created
        // BIO_PENDING is complex macro
        let publicKeyLen = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
        
        guard retval == 1, publicKeyLen > 0 else {
            throw JWKError.createPublicKey
        }
        
        // read the key from the buffer
        let publicKey: UnsafeMutablePointer<UInt8>? = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(publicKeyLen))
        BIO_read(bio, publicKey, Int32(publicKeyLen));
        
        let pk = Data(bytes: publicKey!, count: Int(publicKeyLen))
        return String(data: pk, encoding: .utf8)
    }
    
    private func base64URLToUInt (_ str: String) throws -> UnsafeBufferPointer<UInt8> {

        guard let data = str.base64URLDecode() else {
            throw JWKError.decoding
        }
        let array = [UInt8](data)
        return array.withUnsafeBufferPointer { p in
            return p
        }
    }
}
