"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.openDb = openDb;
const sqlite3_1 = __importDefault(require("sqlite3"));
const sqlite_1 = require("sqlite");
function openDb() {
    return __awaiter(this, void 0, void 0, function* () {
        return (0, sqlite_1.open)({
            filename: './database.db',
            driver: sqlite3_1.default.Database
        });
    });
}
(() => __awaiter(void 0, void 0, void 0, function* () {
    const db = yield openDb();
    yield db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      name TEXT,
      surName TEXT,
      fathName TEXT,
      birthDate TEXT,
      male TEXT,
      female TEXT,
      tel TEXT,
      email TEXT,
      address TEXT,
      city TEXT,
      workBookNum TEXT,
      billNum TEXT,
      passNum TEXT,
      issueDate TEXT,
      issuingOrgan TEXT,
      birthPlace TEXT,
      jmbgNum TEXT,
      jmbgFrom TEXT,
      jmbgTo TEXT,
      pib TEXT,
      compName TEXT,
      compStreetHome TEXT,
      compCity TEXT,
      compAddr TEXT,
      compMunicipal TEXT,
      compRegNum TEXT,
      compRegDate TEXT,
      compBillNum TEXT,
      famName1 TEXT,
      famPassNum1 TEXT,
      famMember1 TEXT,
      famJmbgNum1 TEXT,
      famName2 TEXT,
      famPassNum2 TEXT,
      famMember2 TEXT,
      famJmbgNum2 TEXT,
      famName3 TEXT,
      famPassNum3 TEXT,
      famMember3 TEXT,
      famJmbgNum3 TEXT,
      famName4 TEXT,
      famPassNum4 TEXT,
      famMember4 TEXT,
      famJmbgNum4 TEXT,
      famName5 TEXT,
      famPassNum5 TEXT,
      famMember5 TEXT,
      famJmbgNum5 TEXT,
      submissiveUsers TEXT,
      role TEXT,
      mailIndex TEXT,
      compMailIndex TEXT,
      bankName TEXT,
      billType TEXT,
      educLevel TEXT,
      educTypeDoc TEXT,
      educNameOrg TEXT,
      educDateReciveDoc TEXT,
      educPlaceAndCountryReciveDoc TEXT
  )

    
  `);
}))();
