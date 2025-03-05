import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

export async function openDb() {
  return open({
    filename: './database.db',
    driver: sqlite3.Database
  });
}



(async () => {
  const db = await openDb();
  await db.exec(`
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
})();
