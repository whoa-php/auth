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

use Whoa\Auth\Contracts\Authorization\PolicyAdministration\EvaluationEnum;
use PHPUnit\Framework\TestCase;

/**
 * @package Whoa\Tests\Auth
 */
class EvaluationEnumTest extends TestCase
{
    /**
     * Test to string conversion.
     */
    public function testToString()
    {
        $this->assertNotEmpty(EvaluationEnum::toString(EvaluationEnum::PERMIT));
        $this->assertNotEmpty(EvaluationEnum::toString(EvaluationEnum::DENY));
        $this->assertNotEmpty(EvaluationEnum::toString(EvaluationEnum::INDETERMINATE));
        $this->assertNotEmpty(EvaluationEnum::toString(EvaluationEnum::INDETERMINATE_PERMIT));
        $this->assertNotEmpty(EvaluationEnum::toString(EvaluationEnum::INDETERMINATE_DENY));
        $this->assertNotEmpty(EvaluationEnum::toString(EvaluationEnum::INDETERMINATE_DENY_OR_PERMIT));
        $this->assertEquals('UNKNOWN', EvaluationEnum::toString(-1));
    }
}
