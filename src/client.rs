use chrono::serde::ts_milliseconds;
use chrono::{Date, DateTime, Datelike, Utc};
use failure::Fail;
use hmac::{Hmac, Mac, NewMac};
use serde::de::Deserializer;
use serde::Deserialize;
use serde_repr::Deserialize_repr;
use sha2::Sha512;
use std::fmt::Display;
use std::str;
use std::str::FromStr;

const API_VERSION_PATH: &'static str = "/tapi/v3/";

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Mercado Bitcoin CLient - Request Error: {}", _0)]
    RequestError(#[cause] reqwest::Error),
    #[fail(display = "Mercado Bitcoin CLient - API Error {}", _0)]
    ApiError(#[cause] ApiStatus),
}

/// Mercado Bitcoins possible API statuses
/// See docs: https://www.mercadobitcoin.com.br/trade-api/#resposta-response
#[derive(Deserialize_repr, PartialEq, Debug, Fail)]
#[repr(u32)]
pub enum ApiStatus {
    #[fail(display = "Success")]
    Success = 100,
    #[fail(display = "Trading stopped")]
    TradingHalted = 199,
    #[fail(display = "POST request required")]
    PostRequestRequired = 200,
    #[fail(display = "Invalid TAPI-ID")]
    InvalidTapiID = 201,
    #[fail(display = "Invalid TAPI-MAC")]
    InvalidTapiMac = 202,
    #[fail(display = "Invalid TAPI nonce")]
    InvalidTapiNonce = 203,
    #[fail(display = "Invalid TAPI method")]
    InvalidTapiMethod = 204,
    #[fail(display = "Invalid Param")]
    InvalidParam = 206,
    #[fail(display = "Request limit exceeded")]
    RequestLimitExceeded = 429,
    #[fail(display = "Invalid request")]
    InvalidRequest = 430,
    #[fail(display = "Blocked")]
    RequestBlocked = 431,
    #[fail(display = "Internal Error")]
    InternalError = 500,
    #[fail(display = "Read only key")]
    ReadOnlyKey = 211,
    #[fail(display = "Invlaid coin pair")]
    InvalidCoinPair = 205,
    #[fail(display = "Insuficient BRL balance")]
    InsuficientBrlBalance = 207,
    #[fail(display = "Insuficient Bitcoin balance")]
    InsuficientBitcoinBalance = 215,
    #[fail(display = "Insuficient Litecoin Balance")]
    InsuficientLitecoinBalance = 216,
    #[fail(display = "Insuficient BCash balance")]
    InsuficientBCashBalance = 232,
    #[fail(display = "Insuficient XRP balance")]
    InsuficientXRPBalance = 240,
    #[fail(display = "Insuficient Ethereum balance")]
    InsuficientEthereumBalance = 243,
    #[fail(display = "Invalid Bitcoin quanrtity")]
    InvalidBitcoinQuantity = 222,
    #[fail(display = "Invalid Litecoin quantity")]
    InvalidLitecoinQuantity = 223,
    #[fail(display = "Invalid BCash quantity")]
    InvalidBCashQuantity = 234,
    #[fail(display = "Invalid XRP quantity")]
    InvalidXRPQuantity = 242,
    #[fail(display = "Invalid Ethereum quantity")]
    InvalidEthereumQuantity = 245,
    #[fail(display = "Invalid price")]
    InvalidPrice = 224,
    #[fail(display = "Invalid decimal cases")]
    InvalidDecimalCases = 227,
    #[fail(display = "Order still processing")]
    OrderProcessing = 432,
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Self::RequestError(error)
    }
}

fn from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    T::Err: Display,
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(serde::de::Error::custom)
}

mod mb_date {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{self, Deserialize, Deserializer};

    const FORMAT: &'static str = "%Y-%m-%d %H:%M:%S%.6f";

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let date = format!("{} 23:59:59.004011", s);
        Utc.datetime_from_str(&date, FORMAT)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
pub enum OrderType {
    Buy = 1,
    Sell = 2,
}

impl OrderType {
    fn place_order_name(&self) -> String {
        match self {
            Self::Buy => "place_buy_order".to_string(),
            Self::Sell => "place_sell_order".to_string(),
        }
    }
}

/// Public: The client responsible for initializing the configuration params
/// and making all the networking requests
pub struct Client {
    public_url: Option<String>,
    private_url: Option<String>,
    identifier: Option<String>,
    secret: Option<String>,
}

impl Client {
    /// Public: Function used to initialize a client that can make requests to
    /// both public and private APIs
    pub fn init(
        public_url: String,
        private_url: String,
        identifier: String,
        secret: String,
    ) -> Self {
        Client {
            public_url: Some(public_url),
            private_url: Some(private_url),
            identifier: Some(identifier),
            secret: Some(secret),
        }
    }

    /// Public: Function used to initialize client that can only make requests to public APIs
    pub fn init_public(url: String) -> Self {
        Client {
            public_url: Some(url),
            private_url: None,
            identifier: None,
            secret: None,
        }
    }

    /// Public: Function used to intialize a client that can only make private API requests
    pub fn init_private(url: String, identifier: String, secret: String) -> Self {
        Client {
            public_url: None,
            private_url: Some(url),
            identifier: Some(identifier),
            secret: Some(secret),
        }
    }

    fn public_url(&self) -> String {
        self.public_url.clone().unwrap()
    }

    fn private_url(&self) -> String {
        self.private_url.clone().unwrap()
    }

    fn identifier(&self) -> String {
        self.identifier.clone().unwrap()
    }

    fn secret(&self) -> String {
        self.secret.clone().unwrap()
    }
}

type Query = Vec<(String, String)>;
type HmacSha512 = Hmac<Sha512>;

impl Client {
    fn sign(&self, params: &Query) -> String {
        let params = serde_urlencoded::to_string(params).unwrap();

        let signature_param = format!("{}?{}", API_VERSION_PATH, params);

        let mut mac = HmacSha512::new_varkey(self.secret().clone().as_bytes())
            .expect("HMAC can take key of any size");

        mac.update(signature_param.as_bytes());
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        hex::encode(code_bytes)
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct Ticker {
    #[serde(deserialize_with = "from_str")]
    high: f32,
    #[serde(deserialize_with = "from_str")]
    low: f32,
    #[serde(deserialize_with = "from_str")]
    vol: f32,
    #[serde(deserialize_with = "from_str")]
    pub last: f32,
    #[serde(deserialize_with = "from_str")]
    pub buy: f32,
    #[serde(deserialize_with = "from_str")]
    pub sell: f32,
    #[serde(with = "ts_milliseconds")]
    pub date: DateTime<Utc>,
}

#[derive(Deserialize, Debug)]
pub struct TickerResponse {
    pub ticker: Ticker,
}

impl Client {
    /// GET /<currency>/ticker
    ///     params:
    ///        - currency: BTC | ETH | LTC
    pub async fn ticker(&self, currency: &'static str) -> Result<TickerResponse, Error> {
        let uri = format!("{}/{}/ticker", self.public_url(), currency);
        Ok(reqwest::get(uri.as_str())
            .await?
            .json::<TickerResponse>()
            .await?)
    }
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct DaySummary {
    #[serde(with = "mb_date")]
    pub date: DateTime<Utc>,
    opening: f32,
    pub closing: f32,
    lowest: f32,
    highest: f32,
    volume: f32,
    quantity: f32,
    amount: i32,
    avg_price: f32,
}

impl Client {
    /// GET /<currency>/day-summary/<year>/<month>/<day>
    ///     params:
    ///        - currency: BTC | ETH | LTC
    ///        - year
    ///        - month
    ///        - day
    pub async fn day_summary(
        &self,
        currency: &'static str,
        date: Date<Utc>,
    ) -> Result<DaySummary, Error> {
        let uri = format!(
            "{}/{}/day-summary/{}/{}/{}",
            self.public_url(),
            currency,
            date.year(),
            date.month(),
            date.day()
        );
        Ok(reqwest::get(uri.as_str())
            .await?
            .json::<DaySummary>()
            .await?)
    }
}

#[derive(Deserialize, Debug)]
pub struct Response<Data> {
    pub response_data: Option<Data>,
    pub status_code: ApiStatus,
}

impl<T> Response<T> {
    fn is_success(&self) -> bool {
        match self.status_code {
            ApiStatus::Success => true,
            _ => false,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct OrderbookOrder {
    pub order_id: i64,
    #[serde(deserialize_with = "from_str")]
    pub quantity: f64,
    #[serde(deserialize_with = "from_str")]
    pub limit_price: f64,
    pub is_owner: bool,
}

#[derive(Deserialize, Debug)]
pub struct Orderbook {
    pub bids: Vec<OrderbookOrder>,
    pub asks: Vec<OrderbookOrder>,
}

#[derive(Deserialize, Debug)]
pub struct OrderbookResponse {
    pub orderbook: Orderbook,
}

impl Client {
    /// Fetch the authenticated orderbook
    /// See docs: https://www.mercadobitcoin.com.br/trade-api/#list_orderbook
    pub async fn orderbook(
        &self,
        coin_pair: String,
        full: bool,
    ) -> Result<OrderbookResponse, Error> {
        let ts = Utc::now().timestamp_nanos();

        let params = vec![
            ("tapi_method".to_string(), "list_orderbook".to_string()),
            ("tapi_nonce".to_string(), ts.to_string()),
            ("coin_pair".to_string(), coin_pair),
            ("full".to_string(), full.to_string()),
        ];

        let signature = self.sign(&params);

        let response = reqwest::Client::new()
            .post(&self.private_url())
            .form(&params)
            .header("TAPI-ID", self.identifier())
            .header("TAPI-MAC", signature)
            .send()
            .await?
            .json::<Response<OrderbookResponse>>()
            .await?;

        if response.is_success() {
            return Ok(response.response_data.unwrap());
        }

        Err(Error::ApiError(response.status_code))
    }
}

#[derive(Deserialize_repr, PartialEq, Debug)]
#[repr(u8)]
pub enum OrderStatus {
    Open = 2,
    Cancelled = 3,
    Filled = 4,
}

#[derive(Deserialize, Debug)]
pub struct Order {
    pub order_id: i64,
    pub coin_pair: String,
    pub order_type: OrderType,
    pub status: OrderStatus,
    pub has_fills: bool,
    #[serde(deserialize_with = "from_str")]
    pub quantity: f64,
    #[serde(deserialize_with = "from_str")]
    pub limit_price: f64,
    #[serde(deserialize_with = "from_str")]
    pub executed_quantity: f64,
    #[serde(deserialize_with = "from_str")]
    pub executed_price_avg: f64,
    #[serde(deserialize_with = "from_str")]
    pub fee: f64,
}

#[derive(Deserialize, Debug)]
pub struct OrderResponse {
    pub order: Order,
}

impl Client {
    async fn place_order(
        &self,
        order_type: OrderType,
        quantity: f64,
        limit_price: f64,
        coin_pair: String,
    ) -> Result<OrderResponse, Error> {
        let ts = Utc::now().timestamp_nanos();

        let params = vec![
            ("tapi_method".to_string(), order_type.place_order_name()),
            ("tapi_nonce".to_string(), ts.to_string()),
            ("coin_pair".to_string(), coin_pair),
            ("quantity".to_string(), format!("{:.8}", quantity)),
            ("limit_price".to_string(), format!("{:.2}", limit_price)),
        ];

        let signature = self.sign(&params);

        let response = reqwest::Client::new()
            .post(&self.private_url())
            .form(&params)
            .header("TAPI-ID", self.identifier())
            .header("TAPI-MAC", signature)
            .send()
            .await?
            .json::<Response<OrderResponse>>()
            .await?;

        if response.is_success() {
            return Ok(response.response_data.unwrap());
        }

        Err(Error::ApiError(response.status_code))
    }

    /// Place a limit buy order
    /// See docs: https://www.mercadobitcoin.com.br/trade-api/#place_buy_order
    pub async fn place_buy_order(
        &self,
        quantity: f64,
        limit_price: f64,
        coin_pair: String,
    ) -> Result<OrderResponse, Error> {
        self.place_order(OrderType::Buy, quantity, limit_price, coin_pair)
            .await
    }

    /// Place a limit sell order
    /// See docs: https://www.mercadobitcoin.com.br/trade-api/#place_sell_order
    pub async fn place_sell_order(
        &self,
        quantity: f64,
        limit_price: f64,
        coin_pair: String,
    ) -> Result<OrderResponse, Error> {
        self.place_order(OrderType::Sell, quantity, limit_price, coin_pair)
            .await
    }
}

#[derive(Deserialize, Debug)]
pub struct Balance {
    #[serde(deserialize_with = "from_str")]
    pub available: f64,
    #[serde(deserialize_with = "from_str")]
    pub total: f64,
}

#[derive(Deserialize, Debug)]
pub struct BalancesResponse {
    pub bch: Balance,
    pub brl: Balance,
    pub btc: Balance,
    pub eth: Balance,
    pub ltc: Balance,
    pub xrp: Balance,
    pub mbprk01: Balance,
    pub mbprk02: Balance,
    pub mbprk03: Balance,
    pub mbprk04: Balance,
    pub mbcons01: Balance,
    pub usdc: Balance,
}

#[derive(Deserialize, Debug)]
pub struct WithdrawalLimits {
    pub bch: Balance,
    pub brl: Balance,
    pub btc: Balance,
    pub eth: Balance,
    pub ltc: Balance,
    pub xrp: Balance,
}

#[derive(Deserialize, Debug)]
pub struct AccountInfoResponse {
    pub balance: BalancesResponse,
    pub withdrawal_limits: WithdrawalLimits,
}

impl Client {
    /// Get account info
    /// See docs: https://www.mercadobitcoin.com.br/trade-api/#account-info
    pub async fn get_account_info(&self) -> Result<AccountInfoResponse, Error> {
        let ts = Utc::now().timestamp_nanos();

        let params = vec![
            ("tapi_method".to_string(), "get_account_info".to_string()),
            ("tapi_nonce".to_string(), ts.to_string()),
        ];

        let signature = self.sign(&params);

        let response = reqwest::Client::new()
            .post(&self.private_url())
            .form(&params)
            .header("TAPI-ID", self.identifier())
            .header("TAPI-MAC", signature)
            .send()
            .await?
            .json::<Response<AccountInfoResponse>>()
            .await?;

        if response.is_success() {
            return Ok(response.response_data.unwrap());
        }

        Err(Error::ApiError(response.status_code))
    }
}
