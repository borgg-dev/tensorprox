from pydantic import BaseModel, Field
from uuid import uuid4

class DDoSDetectionTask(BaseModel):
    name: str = "DDOS Detection Challenge"
    query: dict | None = None  # Now a dictionary to store JSON inputs (traffic features)
    reference: str | None = None  # Now binary (0 or 1 for classification)
    task_id: str = Field(default_factory=lambda: str(uuid4()), allow_mutation=False)

    def make_query(self, feature_data: dict, **kwargs) -> dict:
        """Use the input traffic feature data as the query, excluding the 'label'."""
        # Remove the 'label' and 'used' flag from feature_data if it exists
        feature_data_filtered = {k: v for k, v in feature_data.items() if k not in ['label', 'used']}
        self.query = feature_data_filtered
        return self.query

    def make_reference(self, feature_data: dict) -> str:
        """Generate the expected classification result"""
        #Extracts Label from input features and use it as reference
        self.reference = feature_data.get('label', '') #default to None if label is missing
        return self.reference

    def generate_query_reference(self, feature_data: dict) -> tuple[dict, str]:
        """Generates a query (traffic features) and reference (classification)"""
        self.make_query(feature_data=feature_data)
        self.make_reference(feature_data=feature_data)
        return self.query, self.reference

