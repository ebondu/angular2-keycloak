/// <reference types="mocha" />

import 'core-js';
import 'rxjs/Rx';
import { use } from 'chai';
import * as sinonChai from 'sinon-chai';
import { TestBed } from '@angular/core/testing';
import {
  BrowserDynamicTestingModule,
  platformBrowserDynamicTesting
} from '@angular/platform-browser-dynamic/testing';

use(sinonChai);

TestBed.initTestEnvironment(
  BrowserDynamicTestingModule,
  platformBrowserDynamicTesting()
);

declare const require: any;
const testsContext: any = require.context('./', true, /\.spec/);
testsContext.keys().forEach(testsContext);
