<?php

namespace AuthCliJwt;

use Exception;
use AuthCliJwt\lib\ScopeChecker;
use AuthCliJwt\lib\StandardClock;
use Jose\Component\Core\JWK;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Signature\JWS;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

class OAuthCli
{
    private JWK $privateJWK;
    private string $endpoint;
    private array $claims = [];

    public function __construct(
        private string $secretAlg,
        private string $issuer,
        private string $clientAud
    ) {
        $this->setJWKPrivateKey();
    }

    private function setJWKPrivateKey()
    {
        $this->privateJWK = JWKFactory::createFromSecret(
            $this->secretAlg,
            [
                'alg' => 'HS256',
                'use' => 'sig'
            ]
        );
    }

    public function checkOAuth(string $endpoint): array
    {
        $this->endpoint = $endpoint;
        if ($token = self::getBearerToken()) {
            return $this->loadJWS($token);
        } else {
            return [
                'error' => 'token_is_missing',
                'error_description' => 'The bearer token is missing in request.'
            ];
        };
    }

    public function getClaims()
    {
        return $this->claims;
    }

    private function loadJWS(string $tokenJws): array
    {
        try {
            $jws = (new JWSSerializerManager([
                new CompactSerializer(),
            ]))->unserialize($tokenJws);
            $jwsVerifier = new JWSVerifier(new AlgorithmManager([
                new HS256(),
            ]));

            if (!$jwsVerifier->verifyWithKey($jws, $this->privateJWK, 0)) {
                return [
                    'error' => 'signature_invalid',
                    'error_description' => 'The token is not valid. Failed signature verification.',
                ];
            }

            $claims = $this->checkClaims($jws);

            if (array_key_exists('error', $claims)) {
                $claims['error_description'] = 'The token is not valid. Failed claim check';

                return $claims;
            }
            $this->claims = $claims;
            return array_merge($claims, ['token_status' => 'valid']);
        } catch (Exception $e) {
            return [
                'token_status' => 'fail',
                'error' => $e->getMessage(),
            ];
        }
    }

    private function checkClaims(JWS $jws): array
    {
        $claims = json_decode(($jws->getPayload()), true);
        $clock = new StandardClock;
        $claimCheckerManager = new ClaimCheckerManager(
            [
                new NotBeforeChecker($clock),
                new IssuedAtChecker($clock),
                new IssuerChecker([
                    $this->issuer,
                ]),
                new AudienceChecker($this->clientAud),
                new ScopeChecker($this->endpoint),
                new ExpirationTimeChecker($clock),
            ]
        );
        try {
            $checkClaim = $claimCheckerManager->check($claims);
            return array_merge(['access' => 'allowed'], $checkClaim);
        } catch (InvalidClaimException $e) {
            $result['access'] = 'denied';
            $result['error'] = $e->getMessage();
            if ($e->getClaim() === 'exp') {
                $result['status'] = 'expired';
            }
            return $result;
        }
    }

    public static function getBearerToken(): string | false
    {
        $headers = apache_request_headers();
        if (isset($headers['Authorization'])) {
            preg_match('/Bearer(?P<token>.*)/', $headers['Authorization'], $token);
            return trim($token['token']);
        }
        return false;
    }
}
