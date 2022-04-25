'use strict'

const async_crypto = require('../index.js');
const rsa = async_crypto.rsa;

async_crypto.init();

function cleanup(err, eventType) {
  async_crypto.cleanup();
  console.log("Exiting: " + eventType);
}

[`exit`, `SIGINT`, `SIGUSR1`, `SIGUSR2`, `uncaughtException`, `SIGTERM`].forEach((eventType) => {
  process.on(eventType, cleanup.bind(null, eventType));
})


//openssl genrsa -out private.pem 3072
const pemExample = String.raw`-----BEGIN RSA PRIVATE KEY-----
MIIG5AIBAAKCAYEA1kpAu9FYun7qqBfk1vGF55SnXRDYJtWdODdHT9Tg1SGXMy6R
cgFA6FWZeGD++AwPd7+0OVlHtQQmxhn5B2jFBggSMY3jJNswY4YwIZmFOa1xyzjU
jUtE6m8pfT+mWlUR17Qq6mDl0DDbbkPEbVGcm21nOPIGTRr/Q1dykgFcZ1Bw81YL
SjaZ5XVdXRPLc1++EDA4qvf1uLmygwFp2aLIzOyBniWoAO/jJ8N/acApoBgOKbz4
k9WDaffdPPwdBLolGzcbwAn6pQy4j8RtjurdH6Fd4hEiApvDfopfNt+UPI4AdPZE
BB2slL9h5RZO0M/oVzZ856/jKrqrAE3B6/GGsHipWmo7WRsR8xRRQgu63uYdMIwF
qhHpJvlWFk1GNanqODsxXwhp3IWJWa8OF4DXwCRhlQSS+6HbgJLr8iXPtNonEgYK
W4Fy3UKficPgZKAr4v0q3mAaQO6ySNiJbORPJOVVJ6VY64Mn+iKgPJaiVcSnLnuz
lOGbSvkDu6Y2w9PPAgMBAAECggGBAMNbsEZJ5W0oNX+HQP3f9GaadDX5HEXTKuDM
LHwQI+TKGdD0XG6ly+nD2AUR0ICMZjGSmJhL136kSUEC/rANiMkl5Ig+xVydYzDo
bcrD7dwWTo6pwcUKYMqlCxr/QwZJVdnji9he/ERftjyBFXtgErjz9U3J/4qd2Sco
eu+2w+oAQOjmgaZnvsecxsALQshs+ZZCj/b11ZNR3/dk+34I1K1V1Bk8VTx9dgaT
SP48zPYB2C+e8rO7zHF4Ib7uTPo5Q9w4X0Ujsp9eoaTYb7AcnGV0LLQVFjCUrCqY
+LxI9QbzWPDQ3+5aDquDTWD/+hzYaUO1L82RktSNp5rPZjRgM2qbnVdYyUl0w9M7
PIIc+xEm0M7OlpVrD8EHYVAn6C+p4XVYyM5jqKhImYi3y3cOJGK7DVTFuU+Zw5ae
5Oz00ds6M/TkkSzKbQUk3wgqNwHIThYuBJ7GZLZzXotye/mSRI+CBwOKQbp9Bcfy
ubjPjkQYZkc6qj59aUqsZkBa9S3p2QKBwQD/OaesraM82ujsD4eovNyOIK5a1AyZ
8uWMRWIecOLAyjcKvoIBQi2AIeUXG/2xfIy/h608+gi8OVV7Na1WcnYfMydbpQG5
odNLijGRox/XpL9BvHB6ig6Xu5wfv4cRLsZrcMnpDXJK9pX+U/rp5uGy89gikNXR
R8O9icvu0st0TlkQXdiKP3eRqmLzivE04GXPvAaCAU8jQLid8CeP1BfgD6yVWGrP
qxIOrPKc/Qq08ijoixHo8bf7klnDqfYDiaMCgcEA1vDJIBqIgWek+W5TgSuLffUi
rwX0f8w7+CtB5PGuOSGcLQ3UGsiNspW6c7oXr69DzZvMMn8KjY8TFC2vGMMABDAd
RRP7/pyTUQfPGseB46U6I8o3ctHVTlo/mO1SCbJlLxyEIRfugbH5jRzrdqzJT5V+
WJkIa84hlLCc6vvaYsOEsKJ9x6lhsq+TKfr7CcFKhL9/7BSIWPv3TIcc247wzH/m
zghnON60Unz8L58dcAq+9Qb8vAK1GVQ6IBXVtMflAoHBANF0Z373ITgYD39rX1HD
bN3XRD+WNqFBDdGIP3Xr/qtpSLKwldCiluTI7FGCzziRlpC4sBuStwiBpP1wl8iS
Nw5z1KEJUdkeTWF5ECUNUlyO/8ba9xQZqNAtT3tem2ImmQAjmBCC0IFkzMPj989t
g1xxcbcsVc1ir+kk5RAiPoY8pisgWU1buKz6wCpOpJVYczWAgXa/zEqKGvjC1jTb
QpzHQENwRHgZVMBmftUHdXn6Ikh1mUUq2mrDOJezLArLMQKBwEtdI/g4tXJCKAs5
Ttg0r3VbtWyO9vq0XraWXEVtJDxt93eoqJ03gs+CRlz7fACiwHBgV0nBV67o4rSp
jAJvpRrS0AB/kFTnC5RW25w1Jeru7SLNbYG550PQywnQ9Hnn7iiFpCKCZKNfBvQe
lsUGspNQBHwGNHiwTv/2qR6PbjRA/857OwT98/6WJ1CJ6umxt3IyPyVE0cX5mu1f
VpP5W58onYHSWncLR0jBAB+md8joS6pYZ9d4T41xBexoG4WGrQKBwEKh8/3DEKyz
YAQiaAub9KdkLuV1p28ngtqo+I6tmUUXmm/quM4MZwK+vNdqfazziw3a2ZxvBH5X
dqRtTYH2XXmscRFxJScH7ZWgafZweUfe5Gllcr46cT5tUNrltbvI+ANUvEpsllNe
Y2kbAg8eJAZvFEQgvaQWLivUBWUZLkGzA9X074r01zabgSs7HV9arJ+a0QK9a0pP
wRD+npnS9L4rG/qFzu8/lzkzthfJPV2o3O2WBQhDz8Kup56LB8Iuxg==
-----END RSA PRIVATE KEY-----
`

console.time("conversionTime");
rsa.pemPrivKeyToDer(pemExample, function(err, retBuffer) {
  if(err)
    console.log(err)
  else
  {
    console.log("RSA DER size " + retBuffer.length);
    console.log(retBuffer);

    
    console.log("Reverting DER back to PEM");
    rsa.derPrivKeyToPem(retBuffer, function(err, pem) {
      if(err)
        console.log(err);
      else
      {
        console.log("Comparing PEM conversion with expected");
        if(pem === pemExample)
          console.log("  OK");
        else
          console.log("  FAIL");
      }

      console.timeEnd("conversionTime");
    });    
  }
});

console.log("OpenSSL version: " + async_crypto.getOpenSSLVersion());


const buffer = Buffer.from([1,2,3,4,5,6,7]);
rsa.pemPrivKeyToDer(pemExample, function(err, der){
  if(err)
    console.log("To DER error" + err);
  else
  {
    console.time("signVerifyPEMKey");
    rsa.signSHA256(buffer, der, function(err, signed) {
      if(err)
        console.log("Sign ERROR: " + err)
      else
      {
        rsa.verifySHA256(signed, buffer, der, function(err, verified) {
          if(err)
            console.log("Verify ERROR: " + err)
          else
          {
            console.log("verified: " + verified);
            console.timeEnd("signVerifyPEMKey");
          }
        });
      }
    });
  }
});

console.time("signVerifyCreateKey");
rsa.createKey(Number(3072), function(err, key){
  if(err)
    console.log("CreateKey error: " + err);
  else
  {
    rsa.signSHA256(buffer, key, function(err, signed) {
      if(err)
        console.log("Sign ERROR: " + err)
      else
      {
        rsa.verifySHA256(signed, buffer, key, function(err, verified) {
          if(err)
            console.log("Verify ERROR: " + err)
          else
          {
            console.log("verified: " + verified);
            console.timeEnd("signVerifyCreateKey");
          }
        });
      }
    });
  }
});



