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

use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;
use Whoa\Auth\Authorization\PolicyAdministration\AllOf;
use Whoa\Auth\Authorization\PolicyAdministration\AnyOf;
use Whoa\Auth\Authorization\PolicyAdministration\Rule;
use Whoa\Auth\Authorization\PolicyAdministration\Target;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\RuleInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\TargetInterface;
use Whoa\Auth\Contracts\Authorization\PolicyInformation\ContextInterface;
use Whoa\Tests\Auth\Authorization\PolicyEnforcement\Data\ContextProperties;
use Whoa\Tests\Auth\Authorization\PolicyEnforcement\Data\RequestProperties;

/**
 * @package Whoa\Tests\Auth
 */
abstract class General
{
    /** Operation identity */
    public const OPERATION_CREATE = 'create';

    /** Operation identity */
    public const OPERATION_READ = 'read';

    /** Operation identity */
    public const OPERATION_UPDATE = 'update';

    /** Operation identity */
    public const OPERATION_DELETE = 'delete';

    /** Operation identity */
    public const OPERATION_INDEX = 'index';

    /**
     * @param ContextInterface $context
     *
     * @return bool
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public static function isAdmin(ContextInterface $context): bool
    {
        $curUserRole = $context->get(ContextProperties::CONTEXT_CURRENT_USER_ROLE);
        return $curUserRole === 'admin';
    }

    /**
     * @param string|int $key
     * @param string|int|float $value (any scalar)
     * @return TargetInterface
     */
    protected static function target($key, $value)
    {
        return static::targetMulti([$key => $value]);
    }

    /**
     * @param array $properties
     * @return TargetInterface
     */
    protected static function targetMulti(array $properties)
    {
        $target = new Target(new AnyOf([new AllOf($properties)]));

        $stringPairs = [];
        foreach ($properties as $key => $value) {
            $stringPairs[] = "$key=$value";
        }
        $target->setName(implode(',', $stringPairs));

        return $target;
    }

    /**
     * @return TargetInterface
     */
    protected static function targetOperationRead()
    {
        return static::target(RequestProperties::REQUEST_OPERATION, static::OPERATION_READ);
    }

    /**
     * @return TargetInterface
     */
    protected static function targetOperationUpdate()
    {
        return static::target(RequestProperties::REQUEST_OPERATION, static::OPERATION_UPDATE);
    }

    /**
     * @return TargetInterface
     */
    protected static function targetOperationDelete()
    {
        return static::target(RequestProperties::REQUEST_OPERATION, static::OPERATION_DELETE);
    }

    /**
     * @return TargetInterface
     */
    protected static function targetOperationIndex()
    {
        return static::target(RequestProperties::REQUEST_OPERATION, static::OPERATION_INDEX);
    }

    /**
     * @return RuleInterface
     */
    protected static function rulePermit(): RuleInterface
    {
        return (new Rule())->setName('permit');
    }
}
