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

namespace Whoa\Auth\Authorization\PolicyAdministration;

use Whoa\Auth\Contracts\Authorization\PolicyAdministration\AdviceInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\ObligationInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\PolicyInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\RuleCombiningAlgorithmInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\RuleInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\TargetInterface;

use function assert;

/**
 * @package Whoa\Auth
 */
class Policy implements PolicyInterface
{
    /**
     * @var string|null
     */
    private ?string $name;

    /**
     * @var TargetInterface|null
     */
    private ?TargetInterface $target;

    /**
     * @var RuleInterface[]
     */
    private array $rules;

    /**
     * @var RuleCombiningAlgorithmInterface
     */
    private RuleCombiningAlgorithmInterface $combiningAlgorithm;

    /**
     * @var ObligationInterface[]
     */
    private array $obligations;

    /**
     * @var AdviceInterface[]
     */
    private array $advice;

    /**
     * @param RuleInterface[] $rules
     * @param RuleCombiningAlgorithmInterface $combiningAlgorithm
     * @param null|string $name
     * @param TargetInterface|null $target
     * @param ObligationInterface[] $obligations
     * @param AdviceInterface[] $advice
     */
    public function __construct(
        array $rules,
        RuleCombiningAlgorithmInterface $combiningAlgorithm,
        string $name = null,
        TargetInterface $target = null,
        array $obligations = [],
        array $advice = []
    ) {
        $this->setName($name)->setTarget($target)->setRules($rules)->setCombiningAlgorithm($combiningAlgorithm)
            ->setObligations($obligations)->setAdvice($advice);
    }

    /**
     * @inheritdoc
     */
    public function getName(): ?string
    {
        return $this->name;
    }

    /**
     * @param null|string $name
     * @return self
     */
    public function setName(?string $name): self
    {
        $this->name = $name;

        return $this;
    }

    /**
     * @inheritdoc
     */
    public function getTarget(): ?TargetInterface
    {
        return $this->target;
    }

    /**
     * @param TargetInterface|null $target
     * @return self
     */
    public function setTarget(?TargetInterface $target): self
    {
        $this->target = $target;

        return $this;
    }

    /**
     * @inheritdoc
     */
    public function getRules(): array
    {
        return $this->rules;
    }

    /**
     * @param RuleInterface[] $rules
     * @return self
     */
    public function setRules(array $rules): self
    {
        assert(empty($rules) === false);

        $this->rules = $rules;

        return $this;
    }

    /**
     * @inheritdoc
     */
    public function getCombiningAlgorithm(): RuleCombiningAlgorithmInterface
    {
        return $this->combiningAlgorithm;
    }

    /**
     * @param RuleCombiningAlgorithmInterface $combiningAlgorithm
     * @return self
     */
    public function setCombiningAlgorithm(RuleCombiningAlgorithmInterface $combiningAlgorithm): self
    {
        $this->combiningAlgorithm = $combiningAlgorithm;

        return $this;
    }

    /**
     * @inheritdoc
     */
    public function getObligations(): array
    {
        return $this->obligations;
    }

    /**
     * @param ObligationInterface[] $obligations
     * @return self
     */
    public function setObligations(array $obligations): self
    {
        $this->obligations = $obligations;

        return $this;
    }

    /**
     * @inheritdoc
     */
    public function getAdvice(): array
    {
        return $this->advice;
    }

    /**
     * @param AdviceInterface[] $advice
     * @return self
     */
    public function setAdvice(array $advice): self
    {
        $this->advice = $advice;

        return $this;
    }
}
