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
use Whoa\Auth\Authorization\PolicyAdministration\Rule;
use Whoa\Auth\Authorization\PolicyDecision\RuleAlgorithm;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\PolicyInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\RuleInterface;
use Whoa\Tests\Auth\Authorization\PolicyEnforcement\Data\ContextProperties;
use Whoa\Tests\Auth\Authorization\PolicyEnforcement\Data\RequestProperties;

/**
 * The idea about this class is to provide Rules with simple targets that could be replaced with a switch.
 * @package Whoa\Tests\Auth
 */
abstract class Posts extends General
{
    /** Operation identity */
    public const RESOURCE_TYPE = 'posts';

    /**
     * @return PolicyInterface
     */
    public static function getPolicies(): PolicyInterface
    {
        return (new Policy([
            static::onIndex(),
            static::onRead(),
            static::onUpdate(),
            static::onDelete(),
        ], RuleAlgorithm::firstApplicable())
        )
            ->setTarget(static::target(RequestProperties::REQUEST_RESOURCE_TYPE, static::RESOURCE_TYPE))
            ->setName('Posts');
    }

    /**
     * @return RuleInterface
     */
    protected static function onIndex(): RuleInterface
    {
        return (new Rule())->setTarget(static::targetOperationIndex())->setName('index');
    }

    /**
     * @return RuleInterface
     */
    protected static function onRead(): RuleInterface
    {
        return (new Rule())->setTarget(static::targetOperationRead())->setName('read');
    }

    /**
     * @return RuleInterface
     */
    protected static function onUpdate(): RuleInterface
    {
        return (new Rule())->setTarget(static::targetOperationUpdate())->setName('update');
    }

    /**
     * @return RuleInterface
     */
    protected static function onDelete(): RuleInterface
    {
        return (new Rule())->setTarget(static::targetOperationDelete())->setName('delete');
    }
}
