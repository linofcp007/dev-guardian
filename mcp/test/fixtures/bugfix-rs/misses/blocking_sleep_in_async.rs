//! Fixture de MISSES de `bugfix-rs-race-condition-blocking-sleep-in-async`.
//!
//! Este ficheiro e a especificacao do que e codigo CORRETO. Se alguma coisa
//! aqui disparar, e a regra que esta errada.
//!
//! Sete formas, e cada uma existe para tornar uma clausula da regra
//! MENSURAVEL pela ablacao — sem a forma correspondente, remover a clausula
//! nao mudaria nada e o veredicto seria DEAD por falta de fixture, que e a
//! segunda das tres causas de DEAD listadas no CLAUDE.md:
//!
//!   M1  `fn` sincrona                       -> o `pattern-inside`
//!   M2  a correcao prescrita (`.await`)     -> o `pattern` positivo
//!   M3  `thread::spawn(|| ...)`             -> `$SPAWN(|| { ... })`
//!   M4  `spawn_blocking(move || ...)`       -> `$SPAWN(|| { ... })`
//!   M5  `rt.spawn_blocking(|| ...)`         -> `$X.$SPAWN(|| { ... })`
//!   M6  `rt.spawn_blocking(move || ...)`    -> `$X.$SPAWN(|| { ... })`
//!   M7  `spawn_blocking(|| ...)`            -> `$SPAWN(|| { ... })`
//!
//! As grafias com e sem `move` mapeiam para o MESMO ramo, e isso e medido, nao
//! assumido: o frontend de Rust do Semgrep IGNORA o `move` de um closure, nas
//! duas direcoes. Uma versao anterior desta regra enumerava as quatro
//! combinacoes e o passe de PARES da ablacao devolveu MUTUAMENTE REDUNDANTE
//! para {`$SPAWN(||…)`, `$SPAWN(move ||…)`} e para o par gemeo por metodo —
//! cada metade lia DEAD sozinha, e remover as duas era uma regressao. As
//! quatro formas ficam aqui na mesma: sao as quatro codigo correto, e sao elas
//! que provam a simetria.
//!
//! M4 e M7 sao as mais importantes: `spawn_blocking` e a correcao que a
//! propria mensagem da regra prescreve para trabalho bloqueante. Uma regra que
//! acusa a sua propria correcao foi o que matou o candidato `unwrap-in-drop`
//! nesta ronda.
//!
//! E o que NAO esta aqui e tao deliberado quanto o que esta: um
//! `spawn(async move { thread::sleep(d); })` NAO pertence a este ficheiro,
//! porque continua a ser um bug — esse agenda o future no mesmo executor. Vive
//! em `hits/`, como BUG 5.
//!
//! COMPILA: `cargo build`, zero erros, e SEM DEPENDENCIAS EXTERNAS — daqui o
//! `Delay` escrito a mao em vez do `tokio::time::sleep` e o `spawn_blocking`
//! local em vez do do tokio. O que a regra ve e o NOME, nao a crate.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

/// Um sleep assincrono minimo: devolve um future que cede o controlo ao
/// executor em vez de o bloquear. O equivalente de `tokio::time::sleep`, sem
/// a dependencia.
pub struct Delay {
    fired: bool,
}

impl Future for Delay {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.fired {
            Poll::Ready(())
        } else {
            self.fired = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

pub fn async_sleep(_d: Duration) -> Delay {
    Delay { fired: false }
}

/// Equivalente local de `tokio::task::spawn_blocking`.
pub fn spawn_blocking<F: FnOnce() + Send + 'static>(f: F) -> thread::JoinHandle<()> {
    thread::spawn(f)
}

pub struct Runtime;

impl Runtime {
    /// A mesma coisa, mas chamada por metodo num handle — a forma que um
    /// `pattern-not-inside` ancorado no caminho (`tokio::task::spawn_blocking`)
    /// deixa passar. Medido.
    pub fn spawn_blocking<F: FnOnce() + Send + 'static>(&self, f: F) -> thread::JoinHandle<()> {
        thread::spawn(f)
    }
}

/// M1 — CORRETO. Uma funcao sincrona nao tem executor para bloquear. Um
/// backoff aqui e a coisa certa a fazer.
pub fn retry_with_backoff() {
    std::thread::sleep(Duration::from_millis(50));
    thread::sleep(Duration::from_millis(10));
}

/// M2 — CORRETO. A correcao que a mensagem da regra prescreve, sem tipo de
/// retorno.
pub async fn refresh_token_cache() {
    async_sleep(Duration::from_millis(50)).await;
}

/// M2b — CORRETO. A mesma correcao, com tipo de retorno.
pub async fn load_config() -> u32 {
    async_sleep(Duration::from_secs(1)).await;
    7
}

/// M3 — CORRETO. O sleep corre noutra thread do sistema operativo. O executor
/// nao para.
pub async fn warm_up_pool() {
    let _h = thread::spawn(|| {
        thread::sleep(Duration::from_millis(50));
    });
}

/// M4 — CORRETO, E A CORRECAO CANONICA. Trabalho bloqueante empurrado para a
/// pool de blocking, com um `move` closure — a grafia mais comum, porque o
/// closure quase sempre captura alguma coisa.
pub async fn write_report(path: String) {
    let _h = spawn_blocking(move || {
        let _ = path;
        std::thread::sleep(Duration::from_millis(50));
    });
}

/// M5 — CORRETO. A mesma coisa por chamada de metodo.
pub async fn write_report_on(rt: &Runtime) {
    let _h = rt.spawn_blocking(|| {
        thread::sleep(Duration::from_millis(50));
    });
}

/// M6 — CORRETO. Chamada por metodo com `move` closure.
pub async fn write_report_on_owned(rt: &Runtime, path: String) {
    let _h = rt.spawn_blocking(move || {
        let _ = path;
        thread::sleep(Duration::from_millis(50));
    });
}

/// M7 — CORRETO. Chamada livre com closure sem `move`.
pub async fn flush_cache() {
    let _h = spawn_blocking(|| {
        thread::sleep(Duration::from_millis(5));
    });
}
