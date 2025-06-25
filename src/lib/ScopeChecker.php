<?php

declare(strict_types=1);

namespace AuthCliJwt\lib;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;

final class ScopeChecker implements ClaimChecker
{
    private const CLAIM_NAME = 'scope';

    public function __construct(
        private string $endpoint
    ) {}
    public function checkClaim(mixed $value): void
    {
        if (is_null($value)) {
            throw new InvalidClaimException('The claim "scope" is missing', 'scope', $value);
        }

        if (!is_array($value)) {
            throw new InvalidClaimException('The claim "scope" must be a array of endpoints.', 'scope', $value);
        }

        $t = false;
        foreach ($value as $val) {
            if ($this->evaluateClaim($val, $this->endpoint)) {
                $t = true;
            };
        }

        if (!$t) {
            throw new InvalidClaimException('endpoint_not_found', 'scope', $value);
        }
    }

    public function supportedClaim(): string
    {
        return ScopeChecker::CLAIM_NAME;
    }

    private function evaluateClaim(string $claim1, $claim2): bool
    {
        $arr1 = explode('/', $claim1);
        $arr2 = explode('/', $claim2);
        if (count($arr1) !== count($arr2)) {
            return false;
        }
        $i = 0;
        foreach ($arr1 as $item) {
            if ($item !== $arr2[$i] && $item !== '#') {
                return false;
            }
            $i++;
        }
        return true;
    }
}
