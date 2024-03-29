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

namespace Whoa\Auth\Authorization\PolicyDecision\Algorithms;

use Whoa\Auth\Contracts\Authorization\PolicyAdministration\EvaluationEnum;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\RuleCombiningAlgorithmInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\RuleInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\TargetMatchEnum;
use Whoa\Auth\Contracts\Authorization\PolicyInformation\ContextInterface;
use Psr\Log\LoggerInterface;
use RuntimeException;

use function assert;
use function count;
use function is_array;
use function is_callable;
use function is_string;

/**
 * @package Whoa\Auth
 */
abstract class BaseRuleAlgorithm extends BaseAlgorithm implements RuleCombiningAlgorithmInterface
{
    /**
     * @param array $targets
     * @return array
     */
    abstract protected function optimizeTargets(array $targets): array;

    /**
     * @param ContextInterface $context
     * @param array $rulesData
     * @param LoggerInterface|null $logger
     * @return array
     */
    public static function callRuleAlgorithm(
        ContextInterface $context,
        array $rulesData,
        LoggerInterface $logger = null
    ): array {
        return static::callAlgorithm(
            static::getCallable($rulesData),
            $context,
            static::getTargets($rulesData),
            static::getRules($rulesData),
            $logger
        );
    }

    /**
     * @inheritdoc
     */
    public function optimize(array $rules): array
    {
        assert(empty($rules) === false);

        $ruleId = 0;
        $rawTargets = [];
        $encodedRules = [];
        foreach ($rules as $rule) {
            /** @var RuleInterface $rule */
            $rawTargets[$ruleId] = $rule->getTarget();
            $encodedRules[$ruleId] = Encoder::encodeRule($rule);
            $ruleId++;
        }

        $callable = static::METHOD;
        $optimizedTargets = $this->optimizeTargets($rawTargets);

        /** @var callable|array $callable */
        assert(
            $callable !== null && is_array($callable) === true &&
            is_callable($callable) === true && count($callable) === 2 &&
            is_string($callable[0]) === true && is_string($callable[1]) === true
        );

        return [
            static::INDEX_TARGETS => $optimizedTargets,
            static::INDEX_RULES => $encodedRules,
            static::INDEX_CALLABLE => $callable,
        ];
    }

    /**
     * @inheritdoc
     */
    public static function evaluateItem(
        ContextInterface $context,
        int $match,
        array $encodedItem,
        ?LoggerInterface $logger
    ): array {
        return static::evaluateRule($context, $match, $encodedItem, $logger);
    }

    /**
     * @param ContextInterface $context
     * @param int $match
     * @param array $encodedRule
     * @param LoggerInterface|null $logger
     * @return array
     */
    private static function evaluateRule(
        ContextInterface $context,
        int $match,
        array $encodedRule,
        LoggerInterface $logger = null
    ): array {
        assert(Encoder::isRule($encodedRule));

        $ruleName = null;
        if ($logger !== null) {
            $ruleName = Encoder::ruleName($encodedRule);
            $matchName = TargetMatchEnum::toString($match);
            $logger->debug("Rule '$ruleName' evaluation started for match '$matchName'.");
        }

        /** @see http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html #7.11 (table 4) */

        if ($match === TargetMatchEnum::INDETERMINATE) {
            $isPermit = static::evaluateIsPermit($context, $encodedRule);
            $evaluation = $isPermit === true ?
                EvaluationEnum::INDETERMINATE_PERMIT : EvaluationEnum::INDETERMINATE_DENY;
        } elseif ($match === TargetMatchEnum::NO_TARGET || $match === TargetMatchEnum::MATCH) {
            $isPermit = static::evaluateIsPermit($context, $encodedRule);
            try {
                $condition = Encoder::ruleCondition($encodedRule);
                if (static::evaluateLogical($context, $condition) === false) {
                    $evaluation = EvaluationEnum::NOT_APPLICABLE;
                } else {
                    $evaluation = $isPermit === true ? EvaluationEnum::PERMIT : EvaluationEnum::DENY;
                }
            } catch (RuntimeException $exception) {
                $evaluation = $isPermit === true ?
                    EvaluationEnum::INDETERMINATE_PERMIT : EvaluationEnum::INDETERMINATE_DENY;
            }
        } else {
            assert($match === TargetMatchEnum::NOT_MATCH);
            $evaluation = EvaluationEnum::NOT_APPLICABLE;
        }

        if ($logger !== null) {
            $evaluationName = EvaluationEnum::toString($evaluation);
            $logger->info("Rule '$ruleName' evaluated as '$evaluationName'.");
        }

        return static::packEvaluationResult(
            $evaluation,
            Encoder::getFulfillObligations($evaluation, Encoder::ruleObligations($encodedRule)),
            Encoder::getAppliedAdvice($evaluation, Encoder::ruleAdvice($encodedRule))
        );
    }

    /**
     * @param ContextInterface $context
     * @param array $encodedRule
     * @return bool
     */
    private static function evaluateIsPermit(ContextInterface $context, array $encodedRule): bool
    {
        $ruleEffect = Encoder::ruleEffect($encodedRule);

        try {
            $isPermit = static::evaluateLogical($context, $ruleEffect);
        } catch (RuntimeException $exception) {
            $isPermit = false;
        }

        return $isPermit;
    }

    /**
     * @param array $rulesData
     * @return array
     */
    private static function getTargets(array $rulesData): array
    {
        return $rulesData[self::INDEX_TARGETS];
    }

    /**
     * @param array $rulesData
     * @return array
     */
    private static function getRules(array $rulesData): array
    {
        return $rulesData[self::INDEX_RULES];
    }

    /**
     * @param array $rulesData
     * @return callable
     */
    private static function getCallable(array $rulesData): callable
    {
        return $rulesData[self::INDEX_CALLABLE];
    }
}
