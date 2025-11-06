use anyhow::Result;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use flate2::write::GzEncoder;
use flate2::Compression;
#[cfg(feature = "parquet-out")]
use std::fs::File;
#[cfg(feature = "parquet-out")]
// no-op
#[cfg(feature = "parquet-out")]
// use parquet::file::properties::WriterProperties;
#[cfg(feature = "parquet-out")]
use parquet::schema::types::{Type, TypePtr};
#[cfg(feature = "parquet-out")]
use parquet::basic::{Type as PhysicalType, Repetition, LogicalType};
#[cfg(feature = "parquet-out")]
use parquet::file::writer::SerializedFileWriter;
#[cfg(feature = "parquet-out")]
use parquet::column::writer::ColumnWriter;
#[cfg(feature = "parquet-out")]
// use parquet::data_type::ByteArray;
#[cfg(feature = "parquet-out")]
use std::sync::Arc;

#[derive(Serialize, Debug, Clone)]
pub struct ScanRecord {
    pub rtype: String,
    pub data: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ScanResult {
    pub subdomain: String,
    pub answers: Vec<String>,          // 兼容旧字段: 仅提取 A/AAAA IP
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<ScanRecord>>, // 细分记录类型 (A/AAAA/CNAME/TXT)
}

pub trait OutputWriter: Send + Sync {
    fn write(&self, r: &ScanResult) -> Result<()>;
    fn close(&self) -> Result<()> { Ok(()) }
}

pub struct PlainWriter {
    file: Option<Mutex<Box<dyn Write + Send>>>,
    to_stdout: bool,
    detail: bool,
    domain_only: bool,
}

impl PlainWriter {
    pub fn new(path: Option<PathBuf>, to_stdout: bool, detail: bool, gzip: bool, domain_only: bool, append: bool) -> Result<Self> {
        let file = match path {
            Some(p) => {
                let mut oo = OpenOptions::new();
                oo.create(true).write(true);
                if append { oo.append(true); } else { oo.truncate(true); }
                let f = oo.open(p)?;
                let w: Box<dyn Write + Send> = if gzip { Box::new(GzEncoder::new(f, Compression::default())) } else { Box::new(f) };
                Some(Mutex::new(w))
            }
            None => None,
        };
        Ok(PlainWriter { file, to_stdout, detail, domain_only })
    }
}

impl OutputWriter for PlainWriter {
    fn write(&self, r: &ScanResult) -> Result<()> {
        let mut line = if self.domain_only {
            r.subdomain.clone()
        } else if r.answers.is_empty() {
            format!("{}\t[no-result]", r.subdomain)
        } else {
            format!("{}\t{}", r.subdomain, r.answers.join(","))
        };
        if self.detail {
            if let Some(recs) = &r.records {
                let det: Vec<String> = recs.iter().map(|x| format!("{}:{}", x.rtype, x.data)).collect();
                line.push_str("\t");
                line.push_str(&det.join("|"));
            }
        }
        if self.to_stdout { println!("{}", line); }
        if let Some(f) = &self.file {
            let mut guard = f.lock().unwrap();
            writeln!(guard, "{}", line)?;
            guard.flush()?;
        }
        Ok(())
    }
}

pub struct JsonLinesWriter {
    file: Option<Mutex<Box<dyn Write + Send>>>,
    to_stdout: bool,
}

impl JsonLinesWriter {
    pub fn new(path: Option<PathBuf>, to_stdout: bool, gzip: bool, append: bool) -> Result<Self> {
        let file = match path {
            Some(p) => {
                let mut oo = OpenOptions::new();
                oo.create(true).write(true);
                if append { oo.append(true); } else { oo.truncate(true); }
                let f = oo.open(p)?;
                let w: Box<dyn Write + Send> = if gzip { Box::new(GzEncoder::new(f, Compression::default())) } else { Box::new(f) };
                Some(Mutex::new(w))
            }
            None => None,
        };
        Ok(JsonLinesWriter { file, to_stdout })
    }
}

impl OutputWriter for JsonLinesWriter {
    fn write(&self, r: &ScanResult) -> Result<()> {
        let line = serde_json::to_string(r)?;
        if self.to_stdout { println!("{}", line); }
        if let Some(f) = &self.file {
            let mut guard = f.lock().unwrap();
            writeln!(guard, "{}", line)?;
            guard.flush()?;
        }
        Ok(())
    }
}

pub struct CsvWriter {
    file: Mutex<Box<dyn Write + Send>>,
    to_stdout: bool,
    detail: bool,
}

impl CsvWriter {
    pub fn new(path: PathBuf, to_stdout: bool, detail: bool, gzip: bool, append: bool) -> Result<Self> {
        let mut oo = OpenOptions::new();
        oo.create(true).write(true);
        if append { oo.append(true); } else { oo.truncate(true); }
        let f = oo.open(path)?;
        let w: Box<dyn Write + Send> = if gzip { Box::new(GzEncoder::new(f, Compression::default())) } else { Box::new(f) };
        Ok(CsvWriter { file: Mutex::new(w), to_stdout, detail })
        // Parquet placeholder removed; will implement real writer in future.
    }
}

impl OutputWriter for CsvWriter {
    fn write(&self, r: &ScanResult) -> Result<()> {
        let mut guard = self.file.lock().unwrap();
        let mut parts: Vec<String> = vec![r.subdomain.clone(), r.answers.join("|")];
        if self.detail {
            if let Some(recs) = &r.records {
                let det: Vec<String> = recs.iter().map(|x| format!("{}:{}", x.rtype, x.data)).collect();
                parts.push(det.join("|"));
            } else {
                parts.push(String::new());
            }
        }
        let line = parts.join(";");
        if self.to_stdout { println!("{}", line); }
        writeln!(guard, "{}", line)?;
        guard.flush()?;
        Ok(())
    }
}

pub fn build_writers(path: Option<PathBuf>, output_type: &str, to_stdout: bool, detail: bool, gzip: bool, append: bool) -> Result<Vec<Box<dyn OutputWriter>>> {
    let mut v: Vec<Box<dyn OutputWriter>> = Vec::new();
    match output_type {
        "txt" => {
            v.push(Box::new(PlainWriter::new(path, to_stdout, detail, gzip, false, append)?));
        }
        "txt-domain" => {
            v.push(Box::new(PlainWriter::new(path, to_stdout, false, gzip, true, append)?));
        }
        "txt-ks" => {
            v.push(Box::new(KsWriter::new(path, to_stdout, gzip, append)?));
        }
        "json" | "jsonl" => {
            if path.is_none() && !to_stdout {
                return Err(anyhow::anyhow!("jsonl output requires either --output path or enable stdout (omit --not-print)"));
            }
            v.push(Box::new(JsonLinesWriter::new(path, to_stdout, gzip, append)?));
        }
        "csv" => {
            let p = path.ok_or_else(|| anyhow::anyhow!("csv output requires --output path"))?;
            v.push(Box::new(CsvWriter::new(p, to_stdout, detail, gzip, append)?));
        }
        "parquet" => {
            return Err(anyhow::anyhow!("parquet output not implemented yet"));
        }
        other => {
            return Err(anyhow::anyhow!("unsupported output type: {}", other));
        }
    }
    Ok(v)
}

// ksubdomain 风格链式输出：sub => CNAME xxx => CNAME yyy => ip => ip
pub struct KsWriter {
    file: Option<Mutex<Box<dyn Write + Send>>>,
    to_stdout: bool,
}

impl KsWriter {
    pub fn new(path: Option<PathBuf>, to_stdout: bool, gzip: bool, append: bool) -> Result<Self> {
        let file = match path {
            Some(p) => {
                let mut oo = OpenOptions::new();
                oo.create(true).write(true);
                if append { oo.append(true); } else { oo.truncate(true); }
                let f = oo.open(p)?;
                let w: Box<dyn Write + Send> = if gzip { Box::new(GzEncoder::new(f, Compression::default())) } else { Box::new(f) };
                Some(Mutex::new(w))
            }
            None => None,
        };
        Ok(Self { file, to_stdout })
    }
}

impl OutputWriter for KsWriter {
    fn write(&self, r: &ScanResult) -> Result<()> {
        // 收集 CNAME 名称（去重保序）与 A/AAAA IP（去重保序）
        let mut cnames: Vec<String> = Vec::new();
        let mut ips: Vec<String> = Vec::new();
        if let Some(recs) = &r.records {
            for rec in recs.iter() {
                if rec.rtype == "CNAME" {
                    let mut name = rec.data.clone();
                    if name.ends_with('.') { name.pop(); }
                    if !cnames.contains(&name) { cnames.push(name); }
                } else if rec.rtype == "A" || rec.rtype == "AAAA" {
                    if !ips.contains(&rec.data) { ips.push(rec.data.clone()); }
                }
            }
        } else {
            // 回退：无记录详情时，仅使用 answers 作为 IP 列表
            for ip in r.answers.iter() {
                if !ips.contains(ip) { ips.push(ip.clone()); }
            }
        }
        let mut parts: Vec<String> = Vec::new();
        parts.push(r.subdomain.clone());
        for c in cnames { parts.push(format!("CNAME {}", c)); }
        for ip in ips { parts.push(ip); }
        let line = parts.join(" => ");

        if self.to_stdout { println!("{}", line); }
        if let Some(f) = &self.file {
            let mut g = f.lock().unwrap();
            writeln!(g, "{}", line)?;
            g.flush()?;
        }
        Ok(())
    }
}

#[cfg(feature = "parquet-out")]
pub struct ParquetWriter {
    path: PathBuf,
    detail: bool,
    to_stdout: bool,
    // simple columnar buffers (flattened)
    col_subdomain: Mutex<Vec<String>>, 
    col_answers: Mutex<Vec<String>>,   // answers joined by ','
    col_records: Mutex<Vec<String>>,   // when detail=true, records joined as "rtype:data|...", else empty
}

#[cfg(feature = "parquet-out")]
impl ParquetWriter {
    pub fn new(path: PathBuf, detail: bool, to_stdout: bool) -> Result<Self> {
        Ok(Self {
            path,
            detail,
            to_stdout,
            col_subdomain: Mutex::new(Vec::with_capacity(4096)),
            col_answers: Mutex::new(Vec::with_capacity(4096)),
            col_records: Mutex::new(Vec::with_capacity(4096)),
        })
    }
}

#[cfg(feature = "parquet-out")]
impl OutputWriter for ParquetWriter {
    fn write(&self, r: &ScanResult) -> Result<()> {
        if self.to_stdout {
            // for parity with other writers, emit a concise line to stdout
            let mut line = if r.answers.is_empty() {
                format!("{}\t[no-result]", r.subdomain)
            } else {
                format!("{}\t{}", r.subdomain, r.answers.join(","))
            };
            if self.detail {
                if let Some(recs) = &r.records {
                    let det: Vec<String> = recs.iter().map(|x| format!("{}:{}", x.rtype, x.data)).collect();
                    line.push_str("\t");
                    line.push_str(&det.join("|"));
                }
            }
            println!("{}", line);
        }

        {
            let mut subs = self.col_subdomain.lock().unwrap();
            let mut ans = self.col_answers.lock().unwrap();
            let mut rec = self.col_records.lock().unwrap();
            subs.push(r.subdomain.clone());
            ans.push(r.answers.join(","));
            if self.detail {
                if let Some(recs) = &r.records {
                    let det: Vec<String> = recs.iter().map(|x| format!("{}:{}", x.rtype, x.data)).collect();
                    rec.push(det.join("|"));
                } else {
                    rec.push(String::new());
                }
            } else {
                rec.push(String::new());
            }
        }
        Ok(())
    }

    fn close(&self) -> Result<()> {
        // Drain buffers
        let subs = { let mut g = self.col_subdomain.lock().unwrap(); std::mem::take(&mut *g) };
        let answers = { let mut g = self.col_answers.lock().unwrap(); std::mem::take(&mut *g) };
        let records = { let mut g = self.col_records.lock().unwrap(); std::mem::take(&mut *g) };
        let file = File::create(&self.path)?;
        // Build Parquet schema
        let schema: TypePtr = Type::group_type_builder("schema")
            .with_fields(vec![
                Type::primitive_type_builder("subdomain", PhysicalType::BYTE_ARRAY)
                    .with_repetition(Repetition::REQUIRED)
                    .with_logical_type(Some(LogicalType::String))
                    .build()?.into(),
                Type::primitive_type_builder("answers", PhysicalType::BYTE_ARRAY)
                    .with_repetition(Repetition::REQUIRED)
                    .with_logical_type(Some(LogicalType::String))
                    .build()?.into(),
                Type::primitive_type_builder("records", PhysicalType::BYTE_ARRAY)
                    .with_repetition(Repetition::REQUIRED)
                    .with_logical_type(Some(LogicalType::String))
                    .build()?.into(),
            ])
            .build()?.into();
        let props = WriterProperties::builder().build().into();
        let mut writer = SerializedFileWriter::new(file, schema, props)?;
        {
            let mut row_group_writer = writer.next_row_group()?;
            if let Some(mut col_writer) = row_group_writer.next_column()? {
                match col_writer {
                    parquet::file::writer::SerializedColumnWriter::ByteArrayColumnWriter(ref mut c) => {
                        let data: Vec<ByteArray> = subs.into_iter().map(|s| ByteArray::from(s.as_str())).collect();
                        c.write_batch(data.as_slice(), None, None)?;
                    }
                    _ => {}
                }
                row_group_writer.close_column(col_writer)?;
            }
            if let Some(mut col_writer) = row_group_writer.next_column()? {
                match col_writer {
                    parquet::file::writer::SerializedColumnWriter::ByteArrayColumnWriter(ref mut c) => {
                        let data: Vec<ByteArray> = answers.into_iter().map(|s| ByteArray::from(s.as_str())).collect();
                        c.write_batch(data.as_slice(), None, None)?;
                    }
                    _ => {}
                }
                row_group_writer.close_column(col_writer)?;
            }
            if let Some(mut col_writer) = row_group_writer.next_column()? {
                match col_writer {
                    parquet::file::writer::SerializedColumnWriter::ByteArrayColumnWriter(ref mut c) => {
                        let data: Vec<ByteArray> = records.into_iter().map(|s| ByteArray::from(s.as_str())).collect();
                        c.write_batch(data.as_slice(), None, None)?;
                    }
                    _ => {}
                }
                row_group_writer.close_column(col_writer)?;
            }
            row_group_writer.close()?;
        }
        writer.close()?;
        Ok(())
    }
}
