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
use Whoa\Auth\Authorization\PolicyAdministration\Advice;
use Whoa\Auth\Authorization\PolicyAdministration\Logical;
use Whoa\Auth\Authorization\PolicyAdministration\Obligation;
use Whoa\Auth\Authorization\PolicyAdministration\Policy;
use Whoa\Auth\Authorization\PolicyAdministration\Rule;
use Whoa\Auth\Authorization\PolicyDecision\RuleAlgorithm;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\EvaluationEnum;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\MethodInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\PolicyInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\RuleInterface;
use Whoa\Auth\Contracts\Authorization\PolicyInformation\ContextInterface;
use Whoa\Tests\Auth\Authorization\PolicyEnforcement\Data\ContextProperties;
use Whoa\Tests\Auth\Authorization\PolicyEnforcement\Data\RequestProperties;
use Whoa\Tests\Auth\Authorization\PolicyEnforcement\PolicyEnforcementTest;

/**
 * @package Whoa\Tests\Auth
 */
abstract class Comments extends General
{
    /** Operation identity */
    public const RESOURCE_TYPE = 'comments';

    /**
     * @return PolicyInterface
     */
    public static function getPolicies(): PolicyInterface
    {
        return (new Policy([
            static::onIndex(),
            static::onRead(),
            static::onCreate(),
            static::onUpdate(),
            static::onDelete(),
        ], RuleAlgorithm::permitOverrides())
        )
            ->setTarget(static::target(RequestProperties::REQUEST_RESOURCE_TYPE, static::RESOURCE_TYPE))
            ->setName('Comments');
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
    protected static function onCreate(): RuleInterface
    {
        $obligation = new Obligation(EvaluationEnum::PERMIT, [PolicyEnforcementTest::class, 'markObligationAsCalled']);
        $advice = new Advice(EvaluationEnum::PERMIT, [PolicyEnforcementTest::class, 'markAdviceAsCalled']);

        return (new Rule())->setTarget(
            static::targetMulti([
                RequestProperties::REQUEST_OPERATION => static::OPERATION_CREATE,
                ContextProperties::CONTEXT_USER_IS_SIGNED_IN => true,
            ])
        )->setName('create')->setObligations([$obligation])->setAdvice([$advice]);
    }

    /**
     * @return RuleInterface
     */
    protected static function onUpdate(): RuleInterface
    {
        return (new Rule())
            ->setTarget(
                static::targetMulti([
                    RequestProperties::REQUEST_OPERATION => static::OPERATION_UPDATE,
                    ContextProperties::CONTEXT_USER_IS_SIGNED_IN => true,
                ])
            )
            ->setCondition(static::conditionIsCommentOwnerOrAdmin())
            ->setName('update');
    }

    /**
     * @return MethodInterface
     */
    protected static function conditionIsCommentOwnerOrAdmin()
    {
        return new Logical([static::class, 'isCommentOwnerOrAdmin']);
    }

    /**
     * @return RuleInterface
     */
    protected static function onDelete(): RuleInterface
    {
        return (new Rule())
            ->setTarget(
                static::targetMulti([
                    RequestProperties::REQUEST_OPERATION => static::OPERATION_DELETE,
                    ContextProperties::CONTEXT_USER_IS_SIGNED_IN => true,
                ])
            )
            ->setCondition(static::conditionIsCommentOwnerOrAdmin())
            ->setName('delete');
    }

    /**
     * @param ContextInterface $context
     * @return bool
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public static function isCommentOwnerOrAdmin(ContextInterface $context): bool
    {
        $commentId = $context->get(RequestProperties::REQUEST_RESOURCE_IDENTITY);
        // for testing purposes let's pretend current user is owner of comment with ID 123
        $isOwner = $commentId === 123;
        return $isOwner === true || static::isAdmin($context) === true;
    }
}
