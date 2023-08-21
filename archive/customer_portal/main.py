from typing import List
from uuid import UUID
from fastapi import FastAPI, HTTPException
from customer_portal.models import Cluster, Status, ClusterUpdate

app = FastAPI()

db: List[Cluster] = [
    Cluster(id=UUID("20b19db6-6347-488a-821d-2b9b1a236d08"), title="ABC_Cluster", description="ABC_Cluster", username="admin", password="hello", url="http:127.0.0.1", status=Status.onboarding, message="onboarding"),
    Cluster(id=UUID("09c8a2b4-97e0-4dcf-9d46-183d02ac6dc2"), title="DEF_Cluster", description="DEF_Cluster", username="admin", password="hello", url="http:127.0.0.1", status=Status.onboarding, message="onboarding"),
    Cluster(id=UUID("cc4b2f65-d92d-4645-a18c-088987b20036"), title="GHI_Cluster", description="GHI_Cluster", username="admin", password="hello", url="http:127.0.0.1", status=Status.onboarding, message="onboarding")
]

@app.get("/")
async def root():
    return {"Hello": "Mundo"}

@app.get("/api/v1/cluster")
async def fetch_clusters():
    return db;

@app.get("/api/v1/cluster/{cluster_id}")
async def get_cluster(cluster_id: UUID):
    for cluster in db:
        if cluster.id == cluster_id:
            return cluster;
    raise HTTPException(
        status_code=404,
        detail=f"cluster with id: {cluster_id} does not exist."
    )

@app.post("/api/v1/cluster")
async def add_cluster(cluster: Cluster):
    db.append(cluster)
    return db;

@app.delete("/api/v1/cluster/{cluster_id}")
async def delete_cluster(cluster_id: UUID):
    for cluster in db:
        if cluster.id == cluster_id:
            db.remove(cluster)
            return db;
    raise HTTPException(
        status_code=404,
        detail=f"cluster with id: {cluster_id} does not exist."
    )

@app.put("/api/v1/cluster/{cluster_id}")
async def update_cluster(cluster_update: ClusterUpdate, cluster_id: UUID):
    for cluster in db:
        if cluster.id == cluster_id:
            if cluster_update.title is not None:
                cluster.title = cluster_update.title
            if cluster_update.description is not None:
                cluster.description = cluster_update.description
            if cluster_update.username is not None:
                cluster.username = cluster_update.username
            if cluster_update.password is not None:
                cluster.password = cluster_update.password
            if cluster_update.url is not None:
                cluster.url = cluster_update.url
            if cluster_update.message is not None:
                cluster.message = cluster_update.message
            if cluster_update.status is not None:
                cluster.status = cluster_update.status
            return
    raise HTTPException(
        status_code=404,
        detail=f"cluster with id: {cluster_id} does not exist."
    )
            
