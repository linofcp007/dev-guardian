//! Fixture de HITS de `bugfix-rs-race-condition-blocking-sleep-in-async`.
//!
//! Seis bugs, e a distribuicao NAO e arbitraria: QUATRO deles estao em
//! `async fn` SEM tipo de retorno, que e exatamente o que a forma estreita do
//! padrao (`async fn $F(...) -> $R { ... }`) perde. Uma regressao para essa
//! forma passa de 6 para 2 sem produzir um unico erro, e a contagem por
//! ficheiro em `bugfixRulesRs.test.ts` e a unica coisa que a ve.
//!
//! As tres grafias do alvo estao todas aqui, porque o padrao qualificado
//! `std::thread::sleep(...)` casa as tres e uma delas nao e obvia: o `sleep`
//! nu, importado por `use std::thread::sleep`.
//!
//! Os BUGS 5 e 6 sao os subtis, e os dois existem por causa de defeitos que
//! quase foram introduzidos pela propria exclusao da regra:
//!
//!   BUG 5  `spawn(async move { ... })` agenda o future NO MESMO executor, ao
//!          contrario de `spawn_blocking`, por isso continua a ser um bug. Uma
//!          exclusao ancorada so no NOME da chamada engole-o; a exclusao
//!          ancorada no CLOSURE nao.
//!   BUG 6  `retry(|| { ... })` recebe um closure mas nao e um spawn, e o
//!          closure corre em linha. Uma exclusao ancorada so no CLOSURE
//!          engole-o; e o `metavariable-regex` do nome que o salva, e esta e
//!          a unica fixture que o torna mensuravel.
//!
//! Sao simetricos de proposito: cada um prova metade da exclusao, e sem os
//! dois metade dela leria DEAD na ablacao.
//!
//! COMPILA: `cargo build`, zero erros, sem dependencias externas.

use std::future::Future;
use std::thread;
use std::thread::sleep;
use std::time::Duration;

/// BUG 1 — grafia totalmente qualificada, `async fn` sem tipo de retorno.
pub async fn refresh_token_cache() {
    std::thread::sleep(Duration::from_millis(50));
}

/// BUG 2 — grafia curta `thread::sleep`, `async fn` sem tipo de retorno.
/// A resolucao do `use std::thread;` e o que faz o padrao qualificado casar
/// esta linha.
pub async fn drain_outbox() {
    thread::sleep(Duration::from_millis(10));
}

/// BUG 3 — `async fn` COM tipo de retorno. A forma estreita do padrao
/// encontra este e o 4, e perde o 1 e o 2.
pub async fn load_config() -> u32 {
    std::thread::sleep(Duration::from_secs(1));
    7
}

pub struct Worker;

impl Worker {
    /// BUG 4 — dentro de um `impl`, aninhado num `for`, com o `sleep` nu
    /// importado directamente. A pior das quatro: dorme uma vez por iteracao.
    pub async fn retry_batch(&self) -> Result<(), String> {
        for _ in 0..3 {
            sleep(Duration::from_millis(5));
        }
        Ok(())
    }
}

/// Stand-in local de `tokio::spawn`, sem a dependencia: recebe um FUTURE e
/// agenda-o no mesmo executor. Nao e o `spawn_blocking`, que recebe um
/// closure e o corre noutra thread — e a diferenca entre os dois e a razao de
/// a exclusao da regra exigir um closure em vez de so um nome com `spawn`.
pub fn spawn<F: Future<Output = ()> + Send + 'static>(_f: F) {}

/// BUG 5 — o sleep bloqueante dentro de um bloco `async` entregue ao
/// executor. O nome da chamada contem `spawn`, mas o argumento e um future e
/// nao um closure, por isso a tarefa corre na mesma thread do executor e
/// bloqueia-a exatamente como os outros quatro.
pub async fn schedule_cleanup() {
    spawn(async move {
        std::thread::sleep(Duration::from_millis(20));
    });
}

/// Um helper de aplicacao qualquer que corre o closure NA PROPRIA THREAD.
pub fn retry<F: FnOnce()>(f: F) {
    f();
}

/// BUG 6 — o sleep dentro de um closure entregue a uma funcao cujo nome NAO
/// contem `spawn`. E um bug: o `retry` chama o closure em linha, na thread do
/// executor. Esta e a fixture que torna o `metavariable-regex` da exclusao
/// mensuravel — sem ela, a exclusao poderia deixar cair o `metavariable-regex`
/// e ninguem notava, porque nada mais no corpus distingue "chamada com
/// closure" de "chamada com closure cujo nome tem spawn".
pub async fn refresh_index() {
    retry(|| {
        thread::sleep(Duration::from_millis(30));
    });
}
