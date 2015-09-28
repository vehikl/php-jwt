<?php
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
include_once('../src/JWT.php');
include_once('../src/JWK.php');
include_once('../src/ExpiredException.php');
include_once('../src/BeforeValidException.php');
include_once('../src/SignatureInvalidException.php');
class JWTTest extends PHPUnit_Framework_TestCase
{
    public function testEncodeDecode()
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->assertEquals(JWT::decode($msg, 'my_key', array('HS256')), 'abc');
    }

    public function testDecodeFromPython()
    {
        $msg = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Iio6aHR0cDovL2FwcGxpY2F0aW9uL2NsaWNreT9ibGFoPTEuMjMmZi5vbz00NTYgQUMwMDAgMTIzIg.E_U8X2YpMT5K1cEiT_3-IvBYfrdIFIeVYeOqre_Z5Cg';
        $this->assertEquals(
            JWT::decode($msg, 'my_key', array('HS256')),
            '*:http://application/clicky?blah=1.23&f.oo=456 AC000 123'
        );
    }

    public function testDecodeByJWKKeySet()
    {
        $jsKey = '{"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"s1","n":"kWp2zRA23Z3vTL4uoe8kTFptxBVFunIoP4t_8TDYJrOb7D1iZNDXVeEsYKp6ppmrTZDAgd-cNOTKLd4M39WJc5FN0maTAVKJc7NxklDeKc4dMe1BGvTZNG4MpWBo-taKULlYUu0ltYJuLzOjIrTHfarucrGoRWqM0sl3z2-fv9k"}]}';
        $key = JWK::parseKeySet($jsKey);

        $msg = 'eyJraWQiOiJzMSIsImFsZyI6IlJTMjU2In0.eyJzY3AiOlsib3BlbmlkIiwiZW1haWwiLCJwcm9maWxlIiwiYWFzIl0sInN1YiI6InRVQ1l0bmZJQlBXY3JTSmY0eUJmdk4xa3d3NEtHY3kzTElQazFHVnpzRTAiLCJjbG0iOlsiITV2OEgiXSwiaXNzIjoiaHR0cDpcL1wvMTMwLjIxMS4yNDMuMTE0OjgwODBcL2MyaWQiLCJleHAiOjE0NDExMjY1MzksInVpcCI6eyJncm91cHMiOlsiYWRtaW4iLCJhdWRpdCJdfSwiY2lkIjoicGstb2lkYy0wMSJ9.PvYrnf3k1Z0wgRwCgq0WXKaoIv1hHtzBFO5cGfCs6bl4suc6ilwCWmJqRxGYkU2fNTGyMOt3OUnnBEwl6v5qN6jv7zbkVAVKVvbQLxhHC2nXe3izvoCiVaMEH6hE7VTWwnPbX_qO72mCwTizHTJTZGLOsyXLYM6ctdOMf7sFPTI';
        $this->assertEquals(
            JWT::decode($msg, $key, array('RS256')),
            '*:http://application/clicky?blah=1.23&f.oo=456 AC000 123'
        );
    }

    public function testUrlSafeCharacters()
    {
        $encoded = JWT::encode('f?', 'a');
        $this->assertEquals('f?', JWT::decode($encoded, 'a', array('HS256')));
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->setExpectedException('DomainException');
        JWT::encode(pack('c', 128), 'a');
    }

    public function testMalformedJsonThrowsException()
    {
        $this->setExpectedException('DomainException');
        JWT::jsonDecode('this is not valid JSON string');
    }

    public function testExpiredToken()
    {
        $this->setExpectedException('Firebase\JWT\ExpiredException');
        $payload = array(
            "message" => "abc",
            "exp" => time() - 20); // time in the past
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', array('HS256'));
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $payload = array(
            "message" => "abc",
            "nbf" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', array('HS256'));
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $payload = array(
            "message" => "abc",
            "iat" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', array('HS256'));
    }

    public function testValidToken()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + JWT::$leeway + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "exp" => time() - 20); // time in the past
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testExpiredTokenWithLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "exp" => time() - 70); // time far in the past
        $this->setExpectedException('Firebase\JWT\ExpiredException');
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testValidTokenWithList()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256', 'HS512'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithNbf()
    {
        $payload = array(
            "message" => "abc",
            "iat" => time(),
            "exp" => time() + 20, // time in the future
            "nbf" => time() - 20);
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
    }

    public function testValidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "nbf"     => time() + 20); // not before in near (leeway) future
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testInvalidTokenWithNbfLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "nbf"     => time() + 65); // not before too far in future
        $encoded = JWT::encode($payload, 'my_key');
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        JWT::$leeway = 0;
    }

    public function testValidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "iat"     => time() + 20); // issued in near (leeway) future
        $encoded = JWT::encode($payload, 'my_key');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        $this->assertEquals($decoded->message, 'abc');
        JWT::$leeway = 0;
    }

    public function testInvalidTokenWithIatLeeway()
    {
        JWT::$leeway = 60;
        $payload = array(
            "message" => "abc",
            "iat"     => time() + 65); // issued too far in future
        $encoded = JWT::encode($payload, 'my_key');
        $this->setExpectedException('Firebase\JWT\BeforeValidException');
        $decoded = JWT::decode($encoded, 'my_key', array('HS256'));
        JWT::$leeway = 0;
    }

    public function testInvalidToken()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->setExpectedException('Firebase\JWT\SignatureInvalidException');
        $decoded = JWT::decode($encoded, 'my_key2', array('HS256'));
    }

    public function testNullKeyFails()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + JWT::$leeway + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->setExpectedException('InvalidArgumentException');
        $decoded = JWT::decode($encoded, null, array('HS256'));
    }

    public function testEmptyKeyFails()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + JWT::$leeway + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->setExpectedException('InvalidArgumentException');
        $decoded = JWT::decode($encoded, '', array('HS256'));
    }

    public function testRSEncodeDecode()
    {
        $privKey = openssl_pkey_new(array(
            //'config'=>'C:/wamp/bin/apache/Apache2.4.4/conf/openssl.cnf',//Remove this line when test on travis-ci.org
            'digest_alg' => 'sha512',
            'private_key_bits' => 4096,
            'private_key_type' => OPENSSL_KEYTYPE_RSA));
        if($privKey === false)
        {
            $s = openssl_error_string();
            $this->fail("Cannot create private key: $s");
        }
        else
        {
            $msg = JWT::encode('abc', $privKey, 'RS256');
            $pubKey = openssl_pkey_get_details($privKey);
            $pubKey = $pubKey['key'];
            $decoded = JWT::decode($msg, $pubKey, array('RS256'));
            $this->assertEquals($decoded, 'abc');
        }
    }

    public function testKIDChooser()
    {
        $keys = array('1' => 'my_key', '2' => 'my_key2');
        $msg = JWT::encode('abc', $keys['1'], 'HS256', '1');
        $decoded = JWT::decode($msg, $keys, array('HS256'));
        $this->assertEquals($decoded, 'abc');
    }

    public function testArrayAccessKIDChooser()
    {
        $keys = new ArrayObject(array('1' => 'my_key', '2' => 'my_key2'));
        $msg = JWT::encode('abc', $keys['1'], 'HS256', '1');
        $decoded = JWT::decode($msg, $keys, array('HS256'));
        $this->assertEquals($decoded, 'abc');
    }

    public function testNoneAlgorithm()
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->setExpectedException('DomainException');
        JWT::decode($msg, 'my_key', array('none'));
    }

    public function testIncorrectAlgorithm()
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->setExpectedException('DomainException');
        JWT::decode($msg, 'my_key', array('RS256'));
    }

    public function testMissingAlgorithm()
    {
        $msg = JWT::encode('abc', 'my_key');
        $this->setExpectedException('DomainException');
        JWT::decode($msg, 'my_key');
    }

    public function testAdditionalHeaders()
    {
        $msg = JWT::encode('abc', 'my_key', 'HS256', null, array('cty' => 'test-eit;v=1'));
        $this->assertEquals(JWT::decode($msg, 'my_key', array('HS256')), 'abc');        
    }

    public function testInvalidSegmentCount()
    {
        $this->setExpectedException('UnexpectedValueException');
        JWT::decode('brokenheader.brokenbody', 'my_key', array('HS256'));
    }
}
