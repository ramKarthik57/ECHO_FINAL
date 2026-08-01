"""
FastAPI server for ECHO forensic tool
Provides REST API endpoints for the dashboard
"""
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
import uvicorn
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import *
from utils.helpers import load_json, save_json
from backend.packet_capture import PacketCapture
from backend.metadata_extractor import MetadataExtractor
from backend.flow_builder import FlowBuilder
from backend.burst_analyzer import BurstAnalyzer
from backend.endpoint_profiler import EndpointProfiler
from backend.graph_builder import GraphBuilder

from backend.database import DatabaseManager


app = FastAPI(title="ECHO Forensic API", version="1.0.0")

# Database initialization
DB_PATH = os.path.join(DATA_DIR, "echo_forensic.db")
db = DatabaseManager(DB_PATH)

# Enable CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic models
class AnalysisRequest(BaseModel):
    suspect_ip: str
    pcap_file: Optional[str] = PCAP_FILE


class InvestigatorBase(BaseModel):
    badge_number: str
    name: str
    rank: str

class InvestigatorResponse(BaseModel):
    id: int
    name: str
    rank: str

class WarrantBase(BaseModel):
    investigator_id: int
    case_id: str
    target_ip: str
    warrant_number: str
    expiry_date: Optional[str] = None

class LoginRequest(BaseModel):
    badge_number: str
    ip_address: Optional[str] = "127.0.0.1"

class AnalysisStatus(BaseModel):
    status: str
    message: str
    data: Optional[Dict] = None


@app.get("/health")
async def health_check():
    """Service health check endpoint"""
    return {
        "status": "healthy",
        "service": "ECHO Forensic API",
        "version": "1.0.0"
    }


@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "message": "ECHO Forensic API",
        "version": "1.0.0",
        "endpoints": [
            "/analyze",
            "/flows",
            "/bursts",
            "/endpoints",
            "/graph",
            "/correlations"
        ]
    }


@app.post("/analyze", response_model=AnalysisStatus)
async def run_full_analysis(request: AnalysisRequest):
    """
    Run complete forensic analysis pipeline
    
    Steps:
    1. Extract metadata from PCAP
    2. Build flows
    3. Detect bursts
    4. Profile endpoints
    5. Find correlations
    6. Build graph
    """
    try:
        suspect_ip = request.suspect_ip
        pcap_file = request.pcap_file
        
        print(f"[*] Starting analysis for suspect IP: {suspect_ip}")
        
        # Step 1: Extract metadata
        print("[*] Step 1/6: Extracting metadata...")
        extractor = MetadataExtractor()
        metadata = extractor.extract_from_pcap(pcap_file)
        
        if not metadata:
            raise HTTPException(status_code=400, detail="No metadata extracted from PCAP")
        
        extractor.save_metadata()
        
        # Step 2: Build flows
        print("[*] Step 2/6: Building flows...")
        flow_builder = FlowBuilder()
        flows = flow_builder.build_flows(metadata)
        
        if not flows:
            raise HTTPException(status_code=400, detail="No flows built")
        
        flow_builder.save_flows()
        
        # Step 3: Detect bursts
        print("[*] Step 3/6: Detecting bursts...")
        burst_analyzer = BurstAnalyzer()
        bursts = burst_analyzer.detect_bursts_in_flows(flows)
        
        # Step 4: Profile endpoints
        print("[*] Step 4/6: Profiling endpoints...")
        profiler = EndpointProfiler()
        profiles = profiler.profile_endpoints(flows, suspect_ip)
        profiler.save_profiles()
        
        # Step 5: Find correlations
        print("[*] Step 5/6: Finding correlations...")
        correlations = burst_analyzer.find_correlated_bursts(suspect_ip)
        top_correlated = burst_analyzer.get_top_correlated_endpoints(10)
        
        # Step 6: Build graph
        print("[*] Step 6/6: Building relationship graph...")
        graph_builder = GraphBuilder()
        graph = graph_builder.build_graph(flows, profiles, suspect_ip, correlations)
        graph_builder.save_graph()
        
        # Compile results
        results = {
            "suspect_ip": suspect_ip,
            "total_flows": len(flows),
            "total_bursts": len(bursts),
            "total_endpoints": len(profiles),
            "total_correlations": len(correlations),
            "top_correlated_endpoints": top_correlated[:5],
            "graph_stats": graph_builder.get_statistics()
        }
        
        print("[+] Analysis complete!")
        
        return AnalysisStatus(
            status="success",
            message="Analysis completed successfully",
            data=results
        )
        
    except Exception as e:
        print(f"[!] Analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/flows")
async def get_flows():
    """Get all communication flows"""
    flows_data = load_json(FLOWS_FILE)
    
    if not flows_data:
        raise HTTPException(status_code=404, detail="No flows found")
    
    return {"flows": flows_data}


@app.get("/bursts")
async def get_bursts():
    """Get detected bursts"""
    bursts_file = os.path.join(DATA_DIR, "bursts.json")
    bursts_data = load_json(bursts_file)
    
    if not bursts_data:
        return {"bursts": []}
    
    return {"bursts": bursts_data}


@app.get("/endpoints")
async def get_endpoints():
    """Get endpoint profiles"""
    profiles_file = os.path.join(DATA_DIR, "endpoint_profiles.json")
    profiles_data = load_json(profiles_file)
    
    if not profiles_data:
        raise HTTPException(status_code=404, detail="No endpoint profiles found")
    
    return {"endpoints": profiles_data}


@app.get("/endpoints/ranked")
async def get_ranked_endpoints():
    """Get endpoints ranked by suspicion score"""
    profiles_file = os.path.join(DATA_DIR, "endpoint_profiles.json")
    profiles_data = load_json(profiles_file)
    
    if not profiles_data:
        raise HTTPException(status_code=404, detail="No endpoint profiles found")
    
    # Rank endpoints
    profiler = EndpointProfiler()
    profiler.profiles = profiles_data
    ranked = profiler.rank_endpoints_by_suspicion()
    
    return {"ranked_endpoints": ranked}


@app.get("/correlations")
async def get_correlations():
    """Get burst correlations"""
    corr_file = os.path.join(DATA_DIR, "correlations.json")
    corr_data = load_json(corr_file)
    
    if not corr_data:
        return {"correlations": []}
    
    return {"correlations": corr_data}


@app.get("/graph")
async def get_graph():
    """Get relationship graph data"""
    graph_data = load_json(GRAPH_FILE)
    
    if not graph_data:
        raise HTTPException(status_code=404, detail="No graph data found")
    
    return graph_data


@app.get("/metadata")
async def get_metadata():
    """Get packet metadata"""
    metadata = load_json(METADATA_FILE)
    
    if not metadata:
        raise HTTPException(status_code=404, detail="No metadata found")
    
    return {"metadata": metadata, "count": len(metadata)}


@app.post("/login")
async def login(request: LoginRequest):
    """Log an investigator login event"""
    investigator = db.get_investigator_by_badge(request.badge_number)
    if not investigator:
        raise HTTPException(status_code=401, detail="Invalid badge number")
    
    db.log_login(investigator['id'], request.ip_address, "success")
    return {"message": f"Welcome, {investigator['name']}", "investigator_id": investigator['id']}


@app.post("/investigators", response_model=Dict)
async def add_investigator(inv: InvestigatorBase):
    """Add a new investigator"""
    try:
        inv_id = db.add_investigator(inv.badge_number, inv.name, inv.rank)
        return {"id": inv_id, "message": "Investigator added successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/investigators", response_model=List[InvestigatorResponse])
async def get_investigators(sort_by: str = "name", order: str = "ASC"):
    """Get all investigators with sorting"""
    return db.get_investigators(sort_by, order)


@app.post("/warrants", response_model=Dict)
async def add_warrant(warrant: WarrantBase):
    """Add a new warrant"""
    try:
        w_id = db.add_warrant(
            warrant.investigator_id, 
            warrant.case_id, 
            warrant.target_ip, 
            warrant.warrant_number, 
            warrant.expiry_date
        )
        return {"id": w_id, "message": "Warrant added successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/warrants", response_model=List[Dict])
async def get_warrants(sort_by: str = "expiry_date", order: str = "ASC"):
    """Get all warrants with sorting"""
    return db.get_warrants(sort_by, order)


@app.get("/status")
async def get_status():
    """Get analysis status and available data"""
    status = {
        "metadata_exists": os.path.exists(METADATA_FILE),
        "flows_exist": os.path.exists(FLOWS_FILE),
        "graph_exists": os.path.exists(GRAPH_FILE),
        "pcap_exists": os.path.exists(PCAP_FILE)
    }
    
    return {"status": status}


def main():
    """Start the API server"""
    print("=" * 60)
    print("ECHO Forensic API Server")
    print("=" * 60)
    print(f"Starting server on {API_HOST}:{API_PORT}")
    print(f"API docs available at http://{API_HOST}:{API_PORT}/docs")
    print("=" * 60)
    
    uvicorn.run(
        app,
        host=API_HOST,
        port=API_PORT,
        log_level="info"
    )


if __name__ == "__main__":
    main()