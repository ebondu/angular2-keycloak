import { ComponentFixture, TestBed } from '@angular/core/testing';
import { expect } from 'chai';
import { KeycloakModule } from '../src';

describe('component-hello-world component', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [KeycloakModule.forRoot()]
    });
  });
});
