<?php

/**
 * Copyright 2015-2019 info@neomerx.com
 * Modification Copyright 2021-2022 info@whoaphp.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

declare(strict_types=1);

namespace Whoa\Auth\Authorization\PolicyDecision;

use Whoa\Auth\Authorization\PolicyDecision\Algorithms\PoliciesOrSetsDenyOverrides;
use Whoa\Auth\Authorization\PolicyDecision\Algorithms\PoliciesOrSetsDenyUnlessPermit;
use Whoa\Auth\Authorization\PolicyDecision\Algorithms\PoliciesOrSetsFirstApplicable;
use Whoa\Auth\Authorization\PolicyDecision\Algorithms\PoliciesOrSetsPermitOverrides;
use Whoa\Auth\Authorization\PolicyDecision\Algorithms\PoliciesOrSetsPermitUnlessDeny;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\PolicyCombiningAlgorithmInterface;

/**
 * @package Whoa\Auth
 */
abstract class PolicyAlgorithm
{
    /**
     * @return PolicyCombiningAlgorithmInterface
     */
    public static function firstApplicable(): PolicyCombiningAlgorithmInterface
    {
        return new PoliciesOrSetsFirstApplicable();
    }

    /**
     * @return PolicyCombiningAlgorithmInterface
     */
    public static function denyOverrides(): PolicyCombiningAlgorithmInterface
    {
        return new PoliciesOrSetsDenyOverrides();
    }

    /**
     * @return PolicyCombiningAlgorithmInterface
     */
    public static function permitOverrides(): PolicyCombiningAlgorithmInterface
    {
        return new PoliciesOrSetsPermitOverrides();
    }

    /**
     * @return PolicyCombiningAlgorithmInterface
     */
    public static function denyUnlessPermit(): PolicyCombiningAlgorithmInterface
    {
        return new PoliciesOrSetsDenyUnlessPermit();
    }

    /**
     * @return PolicyCombiningAlgorithmInterface
     */
    public static function permitUnlessDeny(): PolicyCombiningAlgorithmInterface
    {
        return new PoliciesOrSetsPermitUnlessDeny();
    }
}
