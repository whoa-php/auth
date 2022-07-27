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

namespace Whoa\Tests\Auth\Authorization\PolicyEnforcement\Data\Policies;

use Whoa\Auth\Authorization\PolicyAdministration\Policy;
use Whoa\Auth\Authorization\PolicyDecision\RuleAlgorithm;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\PolicyInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\TargetInterface;
use Whoa\Tests\Auth\Authorization\PolicyEnforcement\Data\ContextProperties;
use Whoa\Tests\Auth\Authorization\PolicyEnforcement\Data\RequestProperties;

/**
 * @package Whoa\Tests\Auth
 */
abstract class Messaging extends General
{
    /** Operation identity */
    public const OPERATION_SEND = 'send_message';

    /**
     * @return PolicyInterface
     */
    public static function policyCanSendMessage(): PolicyInterface
    {
        return (new Policy([static::rulePermit()], RuleAlgorithm::denyUnlessPermit()))
            ->setTarget(static::targetSendMessage())
            ->setName('Messaging');
    }

    /**
     * @return TargetInterface
     */
    protected static function targetSendMessage(): TargetInterface
    {
        return static::targetMulti([
            RequestProperties::REQUEST_OPERATION => static::OPERATION_SEND,
            ContextProperties::CONTEXT_IS_WORK_TIME => true,
        ]);
    }
}
