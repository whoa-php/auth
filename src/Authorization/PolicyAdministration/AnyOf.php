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

use Whoa\Auth\Contracts\Authorization\PolicyAdministration\AllOfInterface;
use Whoa\Auth\Contracts\Authorization\PolicyAdministration\AnyOfInterface;
use function assert;

/**
 * @package Whoa\Auth
 */
class AnyOf implements AnyOfInterface
{
    /**
     * @var AllOfInterface[]
     */
    private $allOffs;

    /**
     * @param AllOfInterface[] $allOffs
     */
    public function __construct(array $allOffs)
    {
        assert(empty($allOffs) === false);

        $this->allOffs = $allOffs;
    }

    /**
     * @inheritdoc
     */
    public function getAllOfs(): array
    {
        return $this->allOffs;
    }
}
