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

use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;
use Whoa\Auth\Authorization\PolicyDecision\Algorithms\BasePolicyOrSetAlgorithm;
use Whoa\Auth\Authorization\PolicyDecision\Algorithms\DefaultTargetSerializeTrait;
use Whoa\Auth\Authorization\PolicyDecision\Algorithms\Encoder;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\PolicySetInterface;
use Whoa\Auth\Contracts\Authorization\PolicyDecision\PolicyDecisionPointInterface;
use Whoa\Auth\Contracts\Authorization\PolicyInformation\ContextInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\LoggerInterface;

use function assert;

/**
 * @package Whoa\Auth
 */
class PolicyDecisionPoint implements PolicyDecisionPointInterface
{
    use DefaultTargetSerializeTrait;
    use LoggerAwareTrait;

    /**
     * @var array
     */
    private array $encodePolicySet;

    /**
     * @param PolicySetInterface|array $data
     */
    public function __construct($data)
    {
        $data instanceof PolicySetInterface ? $this->initWithPolicySet($data) : $this->initWithData($data);
    }

    /**
     * @param ContextInterface $context
     * @return array
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
    public function evaluate(ContextInterface $context): array
    {
        $logger = $this->getLogger();

        $set = $this->getEncodePolicySet();

        $name = Encoder::policySetName($set);
        $logger === null ?: $logger->debug("Policy Decision Point evaluates '$name' policy set.");

        $target = Encoder::policySetTarget($set);
        $match = $this->evaluateTarget($context, $target, $logger);
        $result = BasePolicyOrSetAlgorithm::evaluateItem($context, $match, $this->getEncodePolicySet(), $logger);

        $logger === null ?: $logger->debug("Policy Decision Point evaluated '$name' policy set.");

        return $result;
    }

    /**
     * @return array
     */
    public function getEncodePolicySet(): array
    {
        return $this->encodePolicySet;
    }

    /**
     * @return LoggerInterface|null
     */
    protected function getLogger(): ?LoggerInterface
    {
        return $this->logger;
    }

    /**
     * @param PolicySetInterface $policySet
     */
    protected function initWithPolicySet(PolicySetInterface $policySet): void
    {
        $this->initWithData(Encoder::encodePolicySet($policySet));
    }

    /**
     * @param array $encodePolicySet
     */
    protected function initWithData(array $encodePolicySet): void
    {
        assert(Encoder::isPolicySet($encodePolicySet));

        $this->setEncodePolicySet($encodePolicySet);
    }

    /**
     * @param array $encodePolicySet
     */
    protected function setEncodePolicySet(array $encodePolicySet): void
    {
        $this->encodePolicySet = $encodePolicySet;
    }
}
