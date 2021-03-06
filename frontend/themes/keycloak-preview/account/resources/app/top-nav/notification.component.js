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
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
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
var core_1 = require("@angular/core");
var toast_notifier_1 = require("./toast.notifier");
var NotificationComponent = /** @class */ (function () {
    function NotificationComponent(toastNotifier) {
        var _this = this;
        this.isVisible = false;
        this.notification = new toast_notifier_1.ToastNotification("");
        toastNotifier.subscribe(function (notification) {
            _this.notification = notification;
            _this.isVisible = true;
            setTimeout(function () {
                _this.isVisible = false;
            }, 8000);
        });
    }
    NotificationComponent = __decorate([
        core_1.Component({
            selector: 'notification',
            templateUrl: './notification.component.html',
            styleUrls: ['./notification.component.css']
        }),
        __metadata("design:paramtypes", [toast_notifier_1.ToastNotifier])
    ], NotificationComponent);
    return NotificationComponent;
}());
exports.NotificationComponent = NotificationComponent;
//# sourceMappingURL=notification.component.js.map