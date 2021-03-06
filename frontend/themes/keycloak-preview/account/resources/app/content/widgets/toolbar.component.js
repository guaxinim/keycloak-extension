"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
/*
 * Copyright 2017 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @author tags. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
var core_1 = require("@angular/core");
var icon_1 = require("../../page/icon");
/**
*
* @author Stan Silvert ssilvert@redhat.com (C) 2017 Red Hat Inc.
*/
var ToolbarComponent = /** @class */ (function () {
    function ToolbarComponent() {
        // TODO: localize in constructor
        this.sortByTooltip = "Sort by...";
        this.sortAscendingTooltip = "Sort Ascending";
        this.sortDescendingTooltip = "Sort Descending";
        this.isSortAscending = true;
        this.filterText = "";
        this.activeView = "LargeCards";
    }
    ToolbarComponent.prototype.ngOnInit = function () {
        if (this.filterProps && this.filterProps.length > 0) {
            this.filterBy = this.filterProps[0];
        }
        if (this.sortProps && this.sortProps.length > 0) {
            this.sortBy = this.sortProps[0];
        }
    };
    ToolbarComponent.prototype.changeView = function (activeView) {
        this.activeView = activeView;
    };
    ToolbarComponent.prototype.toggleSort = function () {
        this.isSortAscending = !this.isSortAscending;
    };
    ToolbarComponent.prototype.changeSortByProp = function (prop) {
        this.sortBy = prop;
    };
    ToolbarComponent.prototype.changeFilterByProp = function (prop) {
        this.filterBy = prop;
        this.filterText = "";
    };
    ToolbarComponent.prototype.selectedFilterClass = function (prop) {
        if (this.filterBy === prop) {
            return "selected";
        }
        else {
            return "";
        }
    };
    ToolbarComponent.prototype.selectedSortByClass = function (prop) {
        if (this.sortBy === prop) {
            return "selected";
        }
        else {
            return "";
        }
    };
    ToolbarComponent.prototype.isIconButton = function (button) {
        return button.label instanceof icon_1.Icon;
    };
    __decorate([
        core_1.Input(),
        __metadata("design:type", Array)
    ], ToolbarComponent.prototype, "filterProps", void 0);
    __decorate([
        core_1.Input(),
        __metadata("design:type", Array)
    ], ToolbarComponent.prototype, "sortProps", void 0);
    __decorate([
        core_1.Input(),
        __metadata("design:type", Array)
    ], ToolbarComponent.prototype, "actionButtons", void 0);
    ToolbarComponent = __decorate([
        core_1.Component({
            moduleId: module.id,
            selector: 'toolbar',
            templateUrl: 'toolbar.html',
            styleUrls: ['toolbar.css']
        })
    ], ToolbarComponent);
    return ToolbarComponent;
}());
exports.ToolbarComponent = ToolbarComponent;
//# sourceMappingURL=toolbar.component.js.map