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

namespace Whoa\Tests\Auth\Authorization\PolicyAdministration;

use Whoa\Auth\Contracts\Authorization\PolicyAdministration\TargetMatchEnum;
use PHPUnit\Framework\TestCase;

/**
 * @package Whoa\Tests\Auth
 */
class TargetMatchEnumTest extends TestCase
{
    /**
     * Test to string conversion.
     */
    public function testToString()
    {
        $this->assertNotEmpty(TargetMatchEnum::toString(TargetMatchEnum::MATCH));
        $this->assertNotEmpty(TargetMatchEnum::toString(TargetMatchEnum::NOT_MATCH));
        $this->assertNotEmpty(TargetMatchEnum::toString(TargetMatchEnum::NO_TARGET));
        $this->assertNotEmpty(TargetMatchEnum::toString(TargetMatchEnum::INDETERMINATE));
        $this->assertEquals('UNKNOWN', TargetMatchEnum::toString(-1));
    }
}
