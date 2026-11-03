<?php

namespace Workbench\App\Orchid\Layouts\User;

use Orchid\Filters\Filter;
use Orchid\Screen\Layouts\Selection;
use Workbench\App\Orchid\Filters\RoleFilter;

class UserFiltersLayout extends Selection
{
    /**
     * @return string[]|Filter[]
     */
    public function filters(): array
    {
        return [
            RoleFilter::class,
        ];
    }
}
