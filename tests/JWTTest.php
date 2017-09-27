<?php
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

class JWTTest extends \PHPUnit\Framework\TestCase
{
    public function testEncodeDecode()
    {
        $msg = JWT::encode(['abc'], 'my_key');
        $this->assertEquals(JWT::decode($msg, 'my_key', array('HS256')), ['abc']);
    }

    public function testDecodeFromPython()
    {
        $msg = 'eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.Iio6aHR0cDovL2FwcGxpY2F0aW9uL2NsaWNreT9ibGFoPTEuMjMmZi5vbz00NTYgQUMwMDAgMTIzIg.E_U8X2YpMT5K1cEiT_3-IvBYfrdIFIeVYeOqre_Z5Cg';
        $this->assertEquals(
            JWT::decode($msg, 'my_key', array('HS256')),
            '*:http://application/clicky?blah=1.23&f.oo=456 AC000 123'
        );
    }

    /**
     * @expectedException Firebase\JWT\ExpiredException
     */
    public function testDecodeByJWKKeySetTokenExpired()
    {
        $jsKey = '{"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"s1","n":"kWp2zRA23Z3vTL4uoe8kTFptxBVFunIoP4t_8TDYJrOb7D1iZNDXVeEsYKp6ppmrTZDAgd-cNOTKLd4M39WJc5FN0maTAVKJc7NxklDeKc4dMe1BGvTZNG4MpWBo-taKULlYUu0ltYJuLzOjIrTHfarucrGoRWqM0sl3z2-fv9k"}]}';
        $key = JWK::parseKeySet($jsKey);

        $msg = 'eyJraWQiOiJzMSIsImFsZyI6IlJTMjU2In0.eyJzY3AiOlsib3BlbmlkIiwiZW1haWwiLCJwcm9maWxlIiwiYWFzIl0sInN1YiI6InRVQ1l0bmZJQlBXY3JTSmY0eUJmdk4xa3d3NEtHY3kzTElQazFHVnpzRTAiLCJjbG0iOlsiITV2OEgiXSwiaXNzIjoiaHR0cDpcL1wvMTMwLjIxMS4yNDMuMTE0OjgwODBcL2MyaWQiLCJleHAiOjE0NDExMjY1MzksInVpcCI6eyJncm91cHMiOlsiYWRtaW4iLCJhdWRpdCJdfSwiY2lkIjoicGstb2lkYy0wMSJ9.PvYrnf3k1Z0wgRwCgq0WXKaoIv1hHtzBFO5cGfCs6bl4suc6ilwCWmJqRxGYkU2fNTGyMOt3OUnnBEwl6v5qN6jv7zbkVAVKVvbQLxhHC2nXe3izvoCiVaMEH6hE7VTWwnPbX_qO72mCwTizHTJTZGLOsyXLYM6ctdOMf7sFPTI';
        JWT::decode($msg, $key, array('RS256'));
    }

    public function testDecodeByJWKKeySet()
    {
        $jsKey = '{"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"s1","n":"kWp2zRA23Z3vTL4uoe8kTFptxBVFunIoP4t_8TDYJrOb7D1iZNDXVeEsYKp6ppmrTZDAgd-cNOTKLd4M39WJc5FN0maTAVKJc7NxklDeKc4dMe1BGvTZNG4MpWBo-taKULlYUu0ltYJuLzOjIrTHfarucrGoRWqM0sl3z2-fv9k"}]}';
        $key = JWK::parseKeySet($jsKey);

        $msg = 'eyJraWQiOiJzMSIsImFsZyI6IlJTMjU2In0.eyJzY3AiOlsib3BlbmlkIiwiZW1haWwiLCJwcm9maWxlIiwiYWFzIl0sInN1YiI6InRVQ1l0bmZJQlBXY3JTSmY0eUJmdk4xa3d3NEtHY3kzTElQazFHVnpzRTAiLCJjbG0iOlsiITV2OEgiXSwiaXNzIjoiaHR0cDpcL1wvMTMwLjIxMS4yNDMuMTE0OjgwODBcL2MyaWQiLCJleHAiOjE0NDExMjY1MzksInVpcCI6eyJncm91cHMiOlsiYWRtaW4iLCJhdWRpdCJdfSwiY2lkIjoicGstb2lkYy0wMSJ9.PvYrnf3k1Z0wgRwCgq0WXKaoIv1hHtzBFO5cGfCs6bl4suc6ilwCWmJqRxGYkU2fNTGyMOt3OUnnBEwl6v5qN6jv7zbkVAVKVvbQLxhHC2nXe3izvoCiVaMEH6hE7VTWwnPbX_qO72mCwTizHTJTZGLOsyXLYM6ctdOMf7sFPTI';
        $this->expectException('Firebase\JWT\ExpiredException');
        $payload = JWT::decode($msg, $key, array('RS256'));
        $this->assertEquals("tUCYtnfIBPWcrSJf4yBfvN1kww4KGcy3LIPk1GVzsE0",$payload->sub);
        $this->assertEquals(1441126539,$payload->exp);
    }

    public function testDecodeByMultiJWKKeySet()
    {
        $jsKey = '{"keys":[{"kty":"RSA","e":"AQAB","use":"sig","kid":"CXup","n":"hrwD-lc-IwzwidCANmy4qsiZk11yp9kHykOuP0yOnwi36VomYTQVEzZXgh2sDJpGgAutdQudgwLoV8tVSsTG9SQHgJjH9Pd_9V4Ab6PANyZNG6DSeiq1QfiFlEP6Obt0JbRB3W7X2vkxOVaNoWrYskZodxU2V0ogeVL_LkcCGAyNu2jdx3j0DjJatNVk7ystNxb9RfHhJGgpiIkO5S3QiSIVhbBKaJHcZHPF1vq9g0JMGuUCI-OTSVg6XBkTLEGw1C_R73WD_oVEBfdXbXnLukoLHBS11p3OxU7f4rfxA_f_72_UwmWGJnsqS3iahbms3FkvqoL9x_Vj3GhuJSf97Q"},{"kty":"EC","use":"sig","crv":"P-256","kid":"yGvt","x":"pvgdqM3RCshljmuCF1D2Ez1w5ei5k7-bpimWLPNeEHI","y":"JSmUhbUTqiFclVLEdw6dz038F7Whw4URobjXbAReDuM"},{"kty":"EC","use":"sig","crv":"P-384","kid":"9nHY","x":"JPKhjhE0Bj579Mgj3Cn3ERGA8fKVYoGOaV9BPKhtnEobphf8w4GSeigMesL-038W","y":"UbJa1QRX7fo9LxSlh7FOH5ABT5lEtiQeQUcX9BW0bpJFlEVGqwec80tYLdOIl59M"},{"kty":"EC","use":"sig","crv":"P-521","kid":"tVzS","x":"AZgkRHlIyNQJlPIwTWdHqouw41k9dS3GJO04BDEnJnd_Dd1owlCn9SMXA-JuXINn4slwbG4wcECbctXb2cvdGtmn","y":"AdBC6N9lpupzfzcIY3JLIuc8y8MnzV-ItmzHQcC5lYWMTbuM9NU_FlvINeVo8g6i4YZms2xFB-B0VVdaoF9kUswC"}]}';
        $key = JWK::parseKeySet($jsKey);

        $msg = 'eyJraWQiOiJDWHVwIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJmOGI2N2NjNDYwMzA3NzdlZmQ4YmNlNmMxYmZlMjljNmMwZjgxOGVjIiwic2NwIjpbIm9wZW5pZCIsIm5hbWUiLCJwcm9maWxlIiwicGljdHVyZSIsImVtYWlsIiwicnMtcGstbWFpbiIsInJzLXBrLXNvIiwicnMtcGstaXNzdWUiLCJycy1way13ZWIiXSwiY2xtIjpbIiE1djhIIl0sImlzcyI6Imh0dHBzOlwvXC9pZC5wcm9qZWN0a2l0Lm5ldFwvYXV0aGVudGljYXRlIiwiZXhwIjoxNDkyMjI4MzM2LCJpYXQiOjE0OTEzNjQzMzYsImNpZCI6ImNpZC1way13ZWIifQ.KW1K-72bMtiNwvyYBgffG6VaG6I59cELGYQR8M2q7HA8dmzliu6QREJrqyPtwW_rDJZbsD3eylvkRinK9tlsMXCOfEJbxLdAC9b4LKOsnsbuXXwsJHWkFG0a7osdW0ZpXJDoMFlO1aosxRGMkaqhf1wIkvQ5PM_EB08LJv7oz64Antn5bYaoajwgvJRl7ChatRDn9Sx5UIElKD1BK4Uw5WdrZwBlWdWZVNCSFhy4F6SdZvi3OBlXzluDwq61RC-pl2iivilJNljYWVrthHDS1xdtaVz4oteHW13-IS7NNEz6PVnzo5nyoPWMAB4JlRnxcfOFTTUqOA2mX5Csg0UpdQ';
        $this->expectException('Firebase\JWT\ExpiredException');
        $payload = JWT::decode($msg, $key, array('RS256'));
        $this->assertEquals("f8b67cc46030777efd8bce6c1bfe29c6c0f818ec",$payload->sub);
        $this->assertEquals(1492228336,$payload->exp);
    }

    public function testUrlSafeCharacters()
    {
        $encoded = JWT::encode(['f?'], 'a');
        $this->assertEquals(['f?'], JWT::decode($encoded, 'a', array('HS256')));
    }

    public function testMalformedUtf8StringsFail()
    {
        $this->expectException('DomainException');
        JWT::encode(array('c', 128), 'a', 'RSA');
    }

    public function testMalformedJsonThrowsException()
    {
        $this->expectException('DomainException');
        JWT::jsonDecode('this is not valid JSON string');
    }

    public function testExpiredToken()
    {
        $this->expectException('Firebase\JWT\ExpiredException');
        $payload = array(
            "message" => "abc",
            "exp" => time() - 20); // time in the past
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', array('HS256'));
    }

    public function testBeforeValidTokenWithNbf()
    {
        $this->expectException('Firebase\JWT\BeforeValidException');
        $payload = array(
            "message" => "abc",
            "nbf" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        JWT::decode($encoded, 'my_key', array('HS256'));
    }

    public function testBeforeValidTokenWithIat()
    {
        $this->expectException('Firebase\JWT\BeforeValidException');
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
        $this->expectException('Firebase\JWT\ExpiredException');
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
        $this->expectException('Firebase\JWT\BeforeValidException');
        JWT::decode($encoded, 'my_key', array('HS256'));
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
        $this->expectException('Firebase\JWT\BeforeValidException');
        JWT::decode($encoded, 'my_key', array('HS256'));
        JWT::$leeway = 0;
    }

    public function testInvalidToken()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException('Firebase\JWT\SignatureInvalidException');
        JWT::decode($encoded, 'my_key2', array('HS256'));
    }

    public function testNullKeyFails()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + JWT::$leeway + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException('InvalidArgumentException');
        JWT::decode($encoded, null, array('HS256'));
    }

    public function testEmptyKeyFails()
    {
        $payload = array(
            "message" => "abc",
            "exp" => time() + JWT::$leeway + 20); // time in the future
        $encoded = JWT::encode($payload, 'my_key');
        $this->expectException('InvalidArgumentException');
        JWT::decode($encoded, '', array('HS256'));
    }

    public function testRSEncodeDecode()
    {
        $privKey = openssl_pkey_new(array(
            'config'=>'C:/wamp64/bin/apache/apache2.4.27/conf/openssl.cnf',//Remove this line when test on travis-ci.org
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
            $msg = JWT::encode(['abc'], $privKey, 'RS256');
            $pubKey = openssl_pkey_get_details($privKey);
            $pubKey = $pubKey['key'];
            $decoded = JWT::decode($msg, $pubKey, array('RS256'));
            $this->assertEquals($decoded, ['abc']);
        }
    }

    public function testKIDChooser()
    {
        $keys = array('1' => 'my_key', '2' => 'my_key2');
        $msg = JWT::encode(['abc'], $keys['1'], 'HS256', '1');
        $decoded = JWT::decode($msg, $keys, array('HS256'));
        $this->assertEquals($decoded, ['abc']);
    }

    public function testArrayAccessKIDChooser()
    {
        $keys = new ArrayObject(array('1' => 'my_key', '2' => 'my_key2'));
        $msg = JWT::encode(['abc'], $keys['1'], 'HS256', '1');
        $decoded = JWT::decode($msg, $keys, array('HS256'));
        $this->assertEquals($decoded, ['abc']);
    }

    public function testNoneAlgorithm()
    {
        $msg = JWT::encode(['abc'], 'my_key');
        $this->expectException('UnexpectedValueException');
        JWT::decode($msg, 'my_key', array('none'));
    }

    public function testIncorrectAlgorithm()
    {
        $msg = JWT::encode(['abc'], 'my_key');
        $this->expectException('UnexpectedValueException');
        JWT::decode($msg, 'my_key', array('RS256'));
    }

    public function testMissingAlgorithm()
    {
        $msg = JWT::encode(['abc'], 'my_key');
        $this->expectException('UnexpectedValueException');
        JWT::decode($msg, 'my_key');
    }

    public function testAdditionalHeaders()
    {
        $msg = JWT::encode(['abc'], 'my_key', 'HS256', null, array('cty' => 'test-eit;v=1'));
        $this->assertEquals(JWT::decode($msg, 'my_key', array('HS256')), ['abc']);
    }

    public function testInvalidSegmentCount()
    {
        $this->expectException('UnexpectedValueException');
        JWT::decode('brokenheader.brokenbody', 'my_key', array('HS256'));
    }
}
