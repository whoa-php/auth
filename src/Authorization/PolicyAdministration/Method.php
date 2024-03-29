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

use Whoa\Auth\Contracts\Authorization\PolicyAdministration\MethodInterface;

use function assert;
use function count;
use function is_array;
use function is_string;

/**
 * @package Whoa\Auth
 */
abstract class Method implements MethodInterface
{
    /**
     * @var callable
     */
    private $staticMethod;

    /**
     * @param callable $staticMethod
     */
    public function __construct(callable $staticMethod)
    {
        assert(
            is_array($staticMethod) === true && count((array)$staticMethod) === 2 &&
            is_string($staticMethod[0]) === true && is_string($staticMethod[1]) === true,
            'Only array form of static callable method is supported.'
        );

        $this->staticMethod = $staticMethod;
    }

    /**
     * @inheritdoc
     */
    public function getCallable(): callable
    {
        return $this->staticMethod;
    }
}
