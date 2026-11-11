
import { createClient } from "npm:@supabase/supabase-js@2";

const headers = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store",
};

const antwort = (meldung: string, status: number) =>
  new Response(JSON.stringify({ error: meldung }), {
    status,
    headers,
  });

Deno.serve(async (req) => {
  if (req.method !== "POST") {
    return antwort("Methode nicht erlaubt", 405);
  }

  try {
    const body = await req.json();

    const benutzername = String(
      body?.benutzername ?? "",
    ).trim().toLowerCase();

    const passwort = body?.passwort;

    if (
      !/^[a-z0-9._-]{3,40}$/.test(benutzername) ||
      typeof passwort !== "string" ||
      passwort.length === 0 ||
      passwort.length > 1024
    ) {
      return antwort("Benutzername oder Passwort falsch", 401);
    }

    const url = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!url || !anonKey || !serviceKey) {
      throw new Error("Serverkonfiguration fehlt");
    }

    const admin = createClient(url, serviceKey, {
      auth: { persistSession: false },
    });

    // Mitarbeiterkonto zum Benutzernamen suchen.
    const { data: mitarbeiter, error: dbFehler } = await admin
      .from("mitarbeiter")
      .select("auth_user_id")
      .eq("benutzername", benutzername)
      .eq("aktiv", true)
      .maybeSingle();

    if (dbFehler || !mitarbeiter?.auth_user_id) {
      return antwort("Benutzername oder Passwort falsch", 401);
    }

    // Prüfen, ob der Benutzer vorübergehend gesperrt ist.
    const { data: gesperrt, error: sperrFehler } =
      await admin.rpc("dkt_login_gesperrt", {
        p_benutzername: benutzername,
      });

    if (sperrFehler) {
      throw new Error("Login-Sperrprüfung fehlgeschlagen");
    }

    if (gesperrt === true) {
      return antwort(
        "Zu viele Anmeldeversuche. Bitte in 15 Minuten erneut versuchen.",
        429
      );
    }

    // Zugehöriges Supabase-Auth-Konto abrufen.
    const { data: konto, error: kontoFehler } =
      await admin.auth.admin.getUserById(
        mitarbeiter.auth_user_id,
      );

    if (kontoFehler || !konto?.user?.email) {
      return antwort("Benutzername oder Passwort falsch", 401);
    }

    // Passwort wird ausschließlich von Supabase Auth geprüft.
    const auth = createClient(url, anonKey, {
      auth: { persistSession: false },
    });

    const { data, error } =
      await auth.auth.signInWithPassword({
        email: konto.user.email,
        password: passwort,
      });

    if (error || !data.session) {
      return antwort("Benutzername oder Passwort falsch", 401);
    }

    return new Response(
      JSON.stringify({
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_in: data.session.expires_in,
        token_type: data.session.token_type,
      }),
      { status: 200, headers },
    );
  } catch {
    return antwort("Anmeldung momentan nicht möglich", 500);
  }
});
